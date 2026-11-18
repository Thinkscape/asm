use super::*;
use serde_json::json;
use crate::generator::{GeneratorConfig, GeneratorRegistry};
use crate::store::GeneratorRecord;
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use rsa::pkcs8::EncodePublicKey;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::LazyLock;
use std::thread::{self, JoinHandle};
use std::time::Instant;

// An ephemeral key generated once in this test process. No fixtures or production
// credentials, keychain reads, environment overrides, or real GitHub connections.
static KEYS: LazyLock<(String, String)> = LazyLock::new(|| {
    let key = rsa::PrivateKey::new(&mut rand::rng(), 2048).unwrap();
    let pem = key.to_pkcs1_pem(LineEnding::LF).unwrap().to_string();
    let public = key.to_public_key().to_public_key_pem(LineEnding::LF).unwrap();
    (pem, public)
});

fn keys() -> &'static (String, String) {
    &KEYS
}

pub(super) fn test_pem() -> &'static str {
    &keys().0
}

fn grant() -> GithubGrant {
    GithubGrant {
        installation_id: 7,
        repositories: vec![GithubRepository { id: 42, full_name: "acme/web".into() }],
        permissions: BTreeMap::from([
            ("contents".into(), GithubPermission::Write),
            ("metadata".into(), GithubPermission::Read),
        ]),
    }
}

fn config() -> GithubAppConfig {
    GithubAppConfig { client_id: "Iv1.test-client".into(), installations: vec![grant()] }
}

fn second_grant() -> GithubGrant {
    GithubGrant {
        installation_id: 19,
        repositories: vec![GithubRepository { id: 88, full_name: "other/site".into() }],
        permissions: BTreeMap::from([("metadata".into(), GithubPermission::Read)]),
    }
}

fn multi_config() -> GithubAppConfig {
    let mut config = config();
    config.installations.push(second_grant());
    config
}

fn token_response(token: &str) -> Value {
    json!({
        "token": token,
        "expires_at": asm_proto::time::fmt_unix(now() + 3600),
        "permissions": {"contents":"write", "metadata":"read"},
        "repositories": [{"id":42,"full_name":"ACME/Renamed"}],
    })
}

fn installation() -> Value {
    json!({"id":7, "account":{"login":"acme"}, "suspended_at":null,
        "permissions":{"contents":"write","metadata":"read"}})
}

fn discovery_token() -> Value {
    json!({"token":"discovery-private", "expires_at":asm_proto::time::fmt_unix(now()+3600),
        "permissions":{"metadata":"read"}})
}

fn listing(total: u64, repositories: Value) -> Value {
    json!({"total_count":total,"repositories":repositories})
}

struct Step {
    method: &'static str,
    path: String,
    status: u16,
    body: String,
    headers: Vec<(&'static str, String)>,
    delay: Duration,
}

impl Step {
    fn new(method: &'static str, path: &str, status: u16, body: Value) -> Self {
        Self { method, path: path.into(), status, body: body.to_string(), headers: vec![], delay: Duration::ZERO }
    }
    fn mint(body: Value) -> Self {
        Self::mint_for(7, body)
    }
    fn mint_for(id: u64, body: Value) -> Self {
        Self::new("POST", &format!("/app/installations/{id}/access_tokens"), 201, body)
    }
    fn page(page: u64, body: Value) -> Self {
        Self::new("GET", &format!("/installation/repositories?per_page=100&page={page}"), 200, body)
    }
    fn revoke(status: u16) -> Self {
        Self::new("DELETE", "/installation/token", status, Value::Null)
    }
}

struct Request {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Value,
}

fn read_chunk(stream: &mut TcpStream, buffer: &mut [u8], deadline: Instant) -> usize {
    loop {
        let remaining = deadline.checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .expect("local provider request read timed out");
        stream.set_read_timeout(Some(remaining)).unwrap();
        match stream.read(buffer) {
            Ok(read) => return read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if matches!(error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) =>
            {
                assert!(Instant::now() < deadline, "local provider request read timed out");
                thread::sleep(Duration::from_millis(1).min(remaining));
            }
            Err(error) => panic!("local provider request read failed: {error}"),
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Request {
    // Darwin can inherit O_NONBLOCK from the listening socket. A read timeout
    // alone does not clear it, so accept-before-write must explicitly block.
    stream.set_nonblocking(false).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut bytes = Vec::new();
    let header_end = loop {
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        let mut buffer = [0; 4096];
        let read = read_chunk(stream, &mut buffer, deadline);
        assert!(read > 0, "request headers ended early");
        bytes.extend_from_slice(&buffer[..read]);
    };
    let header = std::str::from_utf8(&bytes[..header_end]).unwrap();
    let mut lines = header.split("\r\n");
    let mut first = lines.next().unwrap().split_whitespace();
    let method = first.next().unwrap().to_owned();
    let path = first.next().unwrap().to_owned();
    let headers: BTreeMap<_, _> = lines.filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned())).collect();
    let length: usize = headers.get("content-length").map(|value| value.parse().unwrap()).unwrap_or(0);
    while bytes.len() - header_end < length {
        let mut buffer = [0; 4096];
        let read = read_chunk(stream, &mut buffer, deadline);
        assert!(read > 0, "request body ended early");
        bytes.extend_from_slice(&buffer[..read]);
    }
    let body = if length == 0 { Value::Null } else {
        serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap()
    };
    Request { method, path, headers, body }
}

struct Server {
    url: Url,
    thread: JoinHandle<Vec<Request>>,
}

impl Server {
    fn start(steps: Vec<Step>) -> Self {
        // Key generation may be slow in debug builds; do it before the server's
        // bounded accept deadline rather than making the network fixture flaky.
        let _ = keys();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let thread = thread::spawn(move || {
            let mut requests = Vec::new();
            for step in steps {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "expected GitHub request was not sent");
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => panic!("local provider accept failed: {error}"),
                    }
                };
                let request = read_request(&mut stream);
                assert_eq!(request.method, step.method);
                assert_eq!(request.path, step.path);
                requests.push(request);
                if !step.delay.is_zero() { thread::sleep(step.delay); }
                let mut response = format!("HTTP/1.1 {} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n", step.status, step.body.len());
                for (name, value) in step.headers {
                    response.push_str(&format!("{name}: {value}\r\n"));
                }
                response.push_str("\r\n");
                response.push_str(&step.body);
                // Timeout tests deliberately close the client first.
                let _ = stream.write_all(response.as_bytes());
            }
            requests
        });
        Self { url, thread }
    }

    fn generator(&self) -> GithubAppGenerator {
        self.generator_with(&config())
    }

    fn generator_with(&self, config: &GithubAppConfig) -> GithubAppGenerator {
        GithubAppGenerator::with_client_for_tests(config, &keys().0,
            GithubAppGenerator::client_builder().build().unwrap(), self.url.clone()).unwrap()
    }

    fn finish(self) -> Vec<Request> {
        self.thread.join().unwrap()
    }
}

fn assert_headers(request: &Request) {
    assert_eq!(request.headers["accept"], "application/vnd.github+json");
    assert_eq!(request.headers["x-github-api-version"], API_VERSION);
    assert_eq!(request.headers["user-agent"], concat!("asm/", env!("CARGO_PKG_VERSION")));
}

fn assert_jwt(request: &Request) {
    assert_headers(request);
    let jwt = request.headers["authorization"].strip_prefix("Bearer ").unwrap();
    assert_eq!(decode_header(jwt).unwrap().alg, Algorithm::RS256);
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = false;
    let decoded = decode::<Value>(jwt, &DecodingKey::from_rsa_pem(keys().1.as_bytes()).unwrap(), &validation).unwrap();
    assert_eq!(decoded.claims["iss"], config().client_id);
    let issued = decoded.claims["iat"].as_i64().unwrap();
    let expires = decoded.claims["exp"].as_i64().unwrap();
    assert_eq!(expires - issued, 660);
    assert!((now() - 65..=now() - 55).contains(&issued));
    assert!((now() + 595..=now() + 605).contains(&expires));
}

#[test]
fn generator_issue_verifies_rs256_and_exact_narrowed_body() {
    let server = Server::start(vec![Step::mint(token_response("variable.length+format-token"))]);
    let generated = server.generator().issue(&grant()).unwrap();
    assert_eq!(generated.token, "variable.length+format-token");
    assert!(generated.expires_at > now() + 3500);
    assert!(!format!("{generated:?}").contains(&generated.token));
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert_jwt(&requests[0]);
    assert_eq!(requests[0].body, json!({"repository_ids":[42],"permissions":{"contents":"write","metadata":"read"}}));
    assert!(requests[0].body.get("expires_at").is_none());
}

#[test]
fn generator_issues_each_grant_only_against_its_configured_installation() {
    let mut second_response = token_response("other-token");
    second_response["repositories"] = json!([{"id":88, "full_name":"other/site"}]);
    second_response["permissions"] = json!({"metadata":"read"});
    let server = Server::start(vec![
        Step::mint(token_response("first-token")),
        Step::mint_for(19, second_response),
    ]);
    let client = server.generator_with(&multi_config());
    let mut crossed = grant();
    crossed.installation_id = 19;
    assert!(client.issue(&crossed).is_err());
    crossed.repositories = second_grant().repositories;
    assert!(client.issue(&crossed).is_err(), "the other installation has no contents permission");
    assert_eq!(client.issue(&grant()).unwrap().token, "first-token");
    assert_eq!(client.issue(&second_grant()).unwrap().token, "other-token");
    let requests = server.finish();
    requests.iter().for_each(assert_jwt);
    assert_eq!(requests[0].body["repository_ids"], json!([42]));
    assert_eq!(requests[1].body, json!({"repository_ids":[88],"permissions":{"metadata":"read"}}));
}

#[test]
fn generator_lists_paginated_app_installations_without_minting_or_forwarding_credentials() {
    let mut first = Step::new("GET", "/app/installations?per_page=100&page=1", 200,
        json!([{"id":19,"account":{"login":"other"}}]));
    first.headers.push(("Link", "<http://127.0.0.1:1/steal-jwt>; rel=\"next\"".into()));
    let server = Server::start(vec![first,
        Step::new("GET", "/app/installations?per_page=100&page=2", 200,
            json!([{"id":7,"account":{"login":"acme"}}])),
    ]);
    let draft = GithubAppConfig { installations: Vec::new(), ..config() };
    let client = GithubAppGenerator::construct(draft, &keys().0,
        GithubAppGenerator::client_builder().build().unwrap(), server.url.clone()).unwrap();
    assert_eq!(client.list_installations().unwrap(), [
        GithubInstallationAccount { installation_id: 7, account: "acme".into() },
        GithubInstallationAccount { installation_id: 19, account: "other".into() },
    ]);
    server.finish().iter().for_each(assert_jwt);
}

#[test]
fn generator_installation_listing_rejects_duplicate_ids_across_pages() {
    let accounts = json!([{"id":7,"account":{"login":"acme"}}]);
    let mut first = Step::new("GET", "/app/installations?per_page=100&page=1", 200, accounts.clone());
    first.headers.push(("Link", "</app/installations?page=2>; rel=\"next\"".into()));
    let server = Server::start(vec![first,
        Step::new("GET", "/app/installations?per_page=100&page=2", 200, accounts),
    ]);
    let error = server.generator().list_installations().unwrap_err();
    assert!(error.message.contains("invalid installation listing"));
    assert_eq!(server.finish().len(), 2);
}

fn installation_verification(id: u64, account: &str, repositories: Value) -> [Step; 4] {
    let mut response = installation();
    response["id"] = json!(id);
    response["account"]["login"] = json!(account);
    [
        Step::new("GET", &format!("/app/installations/{id}"), 200, response),
        Step::mint_for(id, discovery_token()),
        Step::page(1, listing(repositories.as_array().unwrap().len() as u64, repositories)),
        Step::revoke(204),
    ]
}

#[test]
fn generator_verifies_every_configured_installation_with_its_own_discovery_token() {
    let first = installation_verification(7, "acme", json!([{"id":42,"full_name":"Acme/Web"}]));
    let mut second = installation_verification(19, "other", json!([{"id":88,"full_name":"other/site"}]));
    let mut token = discovery_token();
    token["token"] = json!("second-discovery-private");
    second[1] = Step::mint_for(19, token);
    let server = Server::start(first.into_iter().chain(second).collect());
    assert!(server.generator_with(&multi_config()).verify_installations().unwrap().is_none());
    let requests = server.finish();
    for (four, token) in requests.chunks_exact(4).zip(["discovery-private", "second-discovery-private"]) {
        assert_jwt(&four[0]);
        assert_jwt(&four[1]);
        assert_eq!(four[1].body, json!({"permissions":{"metadata":"read"}}));
        assert_eq!(four[2].headers["authorization"], format!("Bearer {token}"));
        assert_eq!(four[3].headers["authorization"], format!("Bearer {token}"));
    }
}

#[test]
fn generator_rejects_unverified_repository_identity_or_permission_in_any_ceiling() {
    for (repositories, permission, expected) in [
        (json!([{"id":77,"full_name":"other/site"}]), None, "repository ID 88"),
        (json!([{"id":88,"full_name":"other/renamed"}]), None, "repository ID 88"),
        (json!([{"id":88,"full_name":"other/site"}]), Some(GithubPermission::Admin), "permission contents:admin"),
    ] {
        let mut config = multi_config();
        if let Some(permission) = permission {
            config.installations[1].permissions.insert("contents".into(), permission);
        }
        let first = installation_verification(7, "acme", json!([{"id":42,"full_name":"acme/web"}]));
        let second = installation_verification(19, "other", repositories);
        let server = Server::start(first.into_iter().chain(second).collect());
        let error = server.generator_with(&config).verify_installations().unwrap_err();
        assert!(error.message.contains(expected));
        assert!(error.message.contains("installation 19"));
        assert_eq!(server.finish().len(), 8, "invalid selections must still revoke discovery tokens");
    }
}

#[test]
fn generator_connect_discovers_with_metadata_only_then_revokes() {
    let mut page1 = Step::page(1, listing(2, json!([{"id":43,"full_name":"acme/api"}])));
    // Must never follow an arbitrary provider-supplied URL.
    page1.headers.push(("Link", "<http://127.0.0.1:1/steal-token>; rel=\"next\"".into()));
    let server = Server::start(vec![
        Step::new("GET", "/app/installations/7", 200, installation()),
        Step::mint(discovery_token()), page1,
        Step::page(2, listing(2, json!([{"id":42,"full_name":"Acme/Web"}]))),
        Step::revoke(204),
    ]);
    let discovered = server.generator().connect(7).unwrap();
    assert_eq!(discovered.account_login, "acme");
    assert_eq!(discovered.repositories.iter().map(|repo| repo.id).collect::<Vec<_>>(), [42,43]);
    assert_eq!(discovered.repositories[0].full_name, "Acme/Web");
    assert_eq!(discovered.permissions, grant().permissions);
    assert!(discovered.warning.is_none());
    let requests = server.finish();
    assert_jwt(&requests[0]);
    assert_jwt(&requests[1]);
    assert_eq!(requests[1].body, json!({"permissions":{"metadata":"read"}}));
    for request in &requests[2..] {
        assert_headers(request);
        assert_eq!(request.headers["authorization"], "Bearer discovery-private");
    }
}

#[test]
fn generator_connect_refuses_wrong_suspended_or_unverifiable_installation() {
    let mut wrong_id = installation(); wrong_id["id"] = json!(8);
    let mut suspended = installation(); suspended["suspended_at"] = json!("2026-11-01T00:00:00Z");
    let mut missing_suspension = installation(); missing_suspension.as_object_mut().unwrap().remove("suspended_at");
    let mut missing_permissions = installation(); missing_permissions.as_object_mut().unwrap().remove("permissions");
    let mut malformed_permissions = installation(); malformed_permissions["permissions"] = json!({"contents":"none"});
    for response in [wrong_id, suspended, missing_suspension, missing_permissions, malformed_permissions] {
        let server = Server::start(vec![Step::new("GET", "/app/installations/7", 200, response)]);
        assert!(server.generator().connect(7).is_err());
        assert_eq!(server.finish().len(), 1, "never create discovery tokens for an unverified installation");
    }
}

#[test]
fn generator_discovery_refuses_broader_missing_or_invalid_permission_evidence() {
    for permissions in [Some(json!({"metadata":"read","contents":"read"})), Some(json!({})), None] {
        let mut token = discovery_token();
        match permissions {
            Some(value) => token["permissions"] = value,
            None => { token.as_object_mut().unwrap().remove("permissions"); }
        }
        let server = Server::start(vec![Step::new("GET", "/app/installations/7", 200, installation()), Step::mint(token), Step::revoke(204)]);
        let error = server.generator().connect(7).unwrap_err();
        assert!(error.message.contains("metadata-only"));
        let requests = server.finish();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[2].headers["authorization"], "Bearer discovery-private");
    }
}

#[test]
fn generator_discovery_always_cleans_up_and_surfaces_sanitized_failure_warning() {
    let server = Server::start(vec![Step::new("GET", "/app/installations/7", 200, installation()),
        Step::mint(discovery_token()), Step::page(1, listing(0,json!([]))), Step::revoke(500)]);
    let warning = server.generator().connect(7).unwrap().warning.unwrap();
    assert!(warning.contains("HTTP 500"));
    assert!(warning.contains("token provider expiry:"));
    assert!(!warning.contains("discovery-private"));
    server.finish();

    let server = Server::start(vec![Step::new("GET", "/app/installations/7", 200, installation()),
        Step::mint(discovery_token()), Step::page(1, json!({"private-token":"must-not-leak"})), Step::revoke(403)]);
    let error = server.generator().connect(7).unwrap_err();
    assert!(error.message.contains(LISTING_CHANGED));
    assert!(error.message.contains("HTTP 403"));
    assert!(!error.message.contains("must-not-leak"));
    assert!(!error.message.contains("discovery-private"));
    server.finish();
}

#[test]
fn generator_issue_enumerates_omitted_and_incomplete_repository_evidence() {
    for repositories in [None, Some(json!([]))] {
        let mut response = token_response("issued-private");
        match repositories {
            Some(value) => response["repositories"] = value,
            None => { response.as_object_mut().unwrap().remove("repositories"); }
        }
        let server = Server::start(vec![Step::mint(response), Step::page(1, listing(1,json!([{"id":42,"full_name":"new-owner/new-name"}])))]);
        assert_eq!(server.generator().issue(&grant()).unwrap().token, "issued-private");
        let requests = server.finish();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].headers["authorization"], "Bearer issued-private");
    }
}

#[test]
fn generator_issue_requires_exact_permissions_not_narrower_or_broader() {
    let cases = [
        Some(json!({"contents":"read","metadata":"read"})),
        Some(json!({"contents":"admin","metadata":"read"})),
        Some(json!({"contents":"write","metadata":"read","issues":"write"})),
        Some(json!({"contents":"write","metadata":"write"})),
        Some(json!({"contents":"unknown"})),
        Some(json!({"BAD_KEY":"read"})),
        None,
    ];
    for permissions in cases {
        let mut response = token_response("scope-private");
        match permissions {
            Some(value) => response["permissions"] = value,
            None => { response.as_object_mut().unwrap().remove("permissions"); }
        }
        let server = Server::start(vec![Step::mint(response), Step::revoke(204)]);
        let error = server.generator().issue(&grant()).unwrap_err();
        assert_eq!(error.message, OUTSIDE_SCOPE);
        assert!(!error.message.contains("scope-private"));
        assert_eq!(server.finish().len(), 2);
    }
}

#[test]
fn generator_issue_normalizes_implicit_metadata_and_ignores_display_name_changes() {
    let mut response = token_response("opaque");
    response["permissions"] = json!({"contents":"write"});
    let server = Server::start(vec![Step::mint(response)]);
    assert_eq!(server.generator().issue(&grant()).unwrap().token, "opaque");
    server.finish();
}

#[test]
fn generator_issue_refuses_resources_outside_grant_and_revokes_without_retrying() {
    for resources in [
        json!([{"id":41,"full_name":"acme/other"}]),
        json!([{"id":42,"full_name":"acme/web"},{"id":43,"full_name":"acme/other"}]),
        json!([{"id":42,"full_name":"acme/web"},{"id":42,"full_name":"acme/web"}]),
        json!([{"id":0,"full_name":"acme/web"}]),
        json!([{"id":42,"full_name":"invalid-name"}]),
        Value::Null,
    ] {
        let mut response = token_response("resource-private"); response["repositories"] = resources;
        let server = Server::start(vec![Step::mint(response),Step::revoke(204)]);
        assert_eq!(server.generator().issue(&grant()).unwrap_err().message, OUTSIDE_SCOPE);
        let requests = server.finish();
        assert_eq!(requests.len(),2);
        assert_eq!(requests[0].body["repository_ids"],json!([42]));
        assert_eq!(requests[1].headers["authorization"],"Bearer resource-private");
    }
}

#[test]
fn generator_issue_rejects_invalid_or_expired_expiry_and_revokes_obtained_token() {
    for expiry in [Value::Null,json!("not-a-date"),json!("2000-01-01T00:00:00Z"),json!(123)] {
        let mut response = token_response("expiry-private"); response["expires_at"] = expiry;
        let server = Server::start(vec![Step::mint(response),Step::revoke(204)]);
        let error = server.generator().issue(&grant()).unwrap_err();
        assert_eq!(error.message,"GitHub token generation failed (invalid token expiry)");
        assert_eq!(server.finish().len(),2);
    }
    let mut response = token_response(""); response.as_object_mut().unwrap().remove("expires_at");
    let server = Server::start(vec![Step::mint(response)]);
    assert!(server.generator().issue(&grant()).is_err());
    assert_eq!(server.finish().len(),1);
}

#[test]
fn generator_pagination_refuses_every_incomplete_or_changing_listing() {
    let single = json!([{"id":42,"full_name":"acme/web"}]);
    let cases = vec![
        vec![json!({"repositories":single.clone()})],
        vec![json!({"total_count":"1","repositories":single.clone()})],
        vec![json!({"total_count":1})],
        vec![listing(1,Value::Null)],
        vec![listing(1,json!([]))],
        vec![listing(0,single.clone())],
        vec![listing(1,json!([{"id":0,"full_name":"acme/web"}]))],
        vec![listing(1,json!([{"id":42,"full_name":"acme/../web"}]))],
        vec![listing(2,json!([{"id":42,"full_name":"acme/web"},{"id":42,"full_name":"acme/web"}]))],
        vec![listing(2,single.clone()),listing(3,json!([{"id":43,"full_name":"acme/api"}]))],
        vec![listing(2,single.clone()),listing(2,single.clone())],
        vec![listing(2,single),listing(2,json!([]))],
    ];
    for pages in cases {
        let mut response = token_response("listing-private"); response.as_object_mut().unwrap().remove("repositories");
        let mut steps = vec![Step::mint(response)];
        steps.extend(pages.into_iter().enumerate().map(|(index,page)| Step::page(index as u64+1,page)));
        steps.push(Step::revoke(204));
        let server = Server::start(steps);
        let error = server.generator().issue(&grant()).unwrap_err();
        assert_eq!(error.message,LISTING_CHANGED);
        assert!(!error.message.contains("listing-private"));
        let requests = server.finish();
        assert_eq!(requests.last().unwrap().headers["authorization"],"Bearer listing-private");
    }
}

#[test]
fn generator_pagination_rejects_malformed_json_and_exactly_wrong_final_scope() {
    let mut token = token_response("listing-private"); token.as_object_mut().unwrap().remove("repositories");
    let mut malformed = Step::page(1,Value::Null); malformed.body = "{not-json".into();
    let server = Server::start(vec![Step::mint(token.clone()),malformed,Step::revoke(204)]);
    assert_eq!(server.generator().issue(&grant()).unwrap_err().message,LISTING_CHANGED);
    server.finish();
    for (count,repositories) in [(0,json!([])),(1,json!([{"id":43,"full_name":"acme/other"}]))] {
        let server = Server::start(vec![Step::mint(token.clone()),Step::page(1,listing(count,repositories)),Step::revoke(204)]);
        assert_eq!(server.generator().issue(&grant()).unwrap_err().message,OUTSIDE_SCOPE);
        server.finish();
    }
}

#[test]
fn generator_provider_errors_and_redirects_are_sanitized_and_never_retried() {
    for status in [401,403,422,429,500] {
        let server = Server::start(vec![Step::new("POST","/app/installations/7/access_tokens",status,
            json!({"token":"response-secret", "message":"PRIVATE KEY and JWT must never leak"}))]);
        let error = server.generator().issue(&grant()).unwrap_err();
        assert_eq!(error.message,format!("GitHub token generation failed (HTTP {status})"));
        assert!(!format!("{error:?}").contains("response-secret"));
        assert!(!error.message.contains("PRIVATE KEY"));
        assert_eq!(server.finish().len(),1);
    }
    let mut redirect = Step::new("POST","/app/installations/7/access_tokens",302,Value::Null);
    redirect.headers.push(("Location","http://127.0.0.1:1/steal-root-jwt".into()));
    let server = Server::start(vec![redirect]);
    assert_eq!(server.generator().issue(&grant()).unwrap_err().message,"GitHub token generation failed (HTTP 302)");
    assert_eq!(server.finish().len(),1);
}

#[test]
fn generator_revoke_uses_token_auth_and_respects_deadline() {
    let server = Server::start(vec![Step::revoke(204)]);
    server.generator().revoke("revocation-private").unwrap();
    let requests = server.finish();
    assert_eq!(requests[0].headers["authorization"],"Bearer revocation-private");
    assert_headers(&requests[0]);
    assert!(requests[0].body.is_null());

    let server = Server::start(vec![]);
    let generator = server.generator();
    assert_eq!(generator.revoke_with_timeout("not-sent",Duration::ZERO).unwrap_err().message,
        "GitHub token revocation failed (deadline elapsed)");
    assert!(server.finish().is_empty());

    let mut slow = Step::revoke(204); slow.delay = Duration::from_millis(200);
    let server = Server::start(vec![slow]);
    let generator = server.generator();
    let started = Instant::now();
    assert!(generator.revoke_with_timeout("deadline-private",Duration::from_millis(25)).is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
    server.finish();
}

#[test]
fn generator_rejects_invalid_claims_locally_without_network() {
    let server = Server::start(vec![]);
    let generator = server.generator();
    let mut outside = grant(); outside.installation_id = 8;
    assert!(generator.issue(&outside).is_err());
    outside = grant(); outside.repositories[0].id = 43;
    assert!(generator.issue(&outside).is_err());
    outside = grant(); outside.permissions.insert("contents".into(),GithubPermission::Admin);
    assert!(generator.issue(&outside).is_err());
    outside = grant(); outside.repositories.clear();
    assert!(generator.issue(&outside).is_err());
    assert!(server.finish().is_empty());
}

#[test]
fn generator_root_key_validation_is_local_redacted_and_accepts_pkcs8() {
    assert!(validate_private_key(&keys().0).is_ok());
    let key = rsa::PrivateKey::from_pkcs1_pem(&keys().0).unwrap();
    use rsa::pkcs8::EncodePrivateKey;
    let pkcs8 = key.to_pkcs8_pem(LineEnding::LF).unwrap();
    assert!(validate_private_key(pkcs8.as_str()).is_ok());
    let ec_pem = rcgen::KeyPair::generate().unwrap().serialize_pem();
    for invalid in ["", "private-key-never-echo", ec_pem.as_str()] {
        let error = validate_private_key(invalid).unwrap_err();
        assert_eq!(error.message,"GitHub private key must be a valid RSA PEM key of at least 2048 bits");
        assert!(!error.message.contains("private-key-never-echo"));
    }
    let generator = GithubAppGenerator::new(&config(), &keys().0).unwrap();
    assert_eq!(generator.base_url.as_str(), API_BASE);
}

#[test]
fn generator_client_construction_is_independent_of_core_startup() {
    // A fresh process cannot inherit Core::start's process-global TLS setup.
    // Running only the direct-construction test keeps this regression independent
    // of test order and concurrent tests that happen to install a provider.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "generator::github::tests::generator_root_key_validation_is_local_redacted_and_accepts_pkcs8",
            "--test-threads=1",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "direct provider construction failed without Core startup:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn generator_registry_loads_ready_without_remote_access_and_retains_provider_on_rename() {
    let registry = GeneratorRegistry::new();
    let workspace = tempfile::tempdir().unwrap();
    let runner = crate::generator::gcloud_cli::GcloudRunner::new(workspace.path().join("gcloud")).unwrap();
    registry.load_with(vec![GeneratorRecord { id:"one".into(),name:"release-bot".into(),revision:1,position:0,
        config:GeneratorConfig::GithubApp(config()) }], &runner, |id,kind| {
        assert_eq!((id,kind),("one",crate::vault::creds::GITHUB_PRIVATE_KEY));
        Ok(Some(keys().0.clone()))
    });
    let mut entry = registry.get("one").unwrap();
    assert_eq!(entry.status(),crate::vault::VaultStatus::Ready);
    let original = entry.client().unwrap();
    entry.record.name = "release-bot-renamed".into();
    registry.insert(entry);
    assert!(std::sync::Arc::ptr_eq(&original,&registry.get("one").unwrap().client().unwrap()));
    registry.mark_unavailable("one","credential restoration failed; edit the generator");
    assert!(registry.get("one").unwrap().client().is_err());
    assert_eq!(registry.entries().len(),1);
}

#[test]
fn generator_partial_scope_evidence_is_enumerated_under_the_new_token() {
    let mut approved = grant();
    approved.repositories.push(GithubRepository { id: 43, full_name: "acme/api".into() });
    let mut configured = config();
    configured.installations[0] = approved.clone();
    let server = Server::start(vec![
        Step::mint(token_response("partial-private")),
        Step::page(1, listing(2, json!([{"id":43,"full_name":"acme/api"}]))),
        Step::page(2, listing(2, json!([{"id":42,"full_name":"acme/web"}]))),
    ]);
    let generator = GithubAppGenerator::with_client_for_tests(&configured, &keys().0,
        GithubAppGenerator::client_builder().build().unwrap(), server.url.clone()).unwrap();
    assert_eq!(generator.issue(&approved).unwrap().token, "partial-private");
    let requests = server.finish();
    assert_eq!(requests[0].body["repository_ids"], json!([42,43]));
    for request in &requests[1..] {
        assert_eq!(request.headers["authorization"], "Bearer partial-private");
    }
}

#[test]
fn generator_discovery_invalid_expiry_still_revokes_obtained_token() {
    for expires_at in [json!("expired"), json!("2000-01-01T00:00:00Z"), Value::Null] {
        let mut response = discovery_token();
        response["expires_at"] = expires_at;
        let server = Server::start(vec![
            Step::new("GET", "/app/installations/7", 200, installation()),
            Step::mint(response), Step::revoke(204),
        ]);
        let error = server.generator().connect(7).unwrap_err();
        assert_eq!(error.message, "GitHub repository discovery failed (invalid token expiry)");
        assert!(!error.message.contains("discovery-private"));
        assert_eq!(server.finish().last().unwrap().headers["authorization"], "Bearer discovery-private");
    }
}

#[test]
fn generator_bad_response_and_network_errors_never_expose_provider_body() {
    let mut step = Step::mint(Value::Null);
    step.body = "PRIVATE KEY, JWT, token: malformed JSON".into();
    let server = Server::start(vec![step]);
    let error = server.generator().issue(&grant()).unwrap_err();
    assert_eq!(error.message, "GitHub token generation failed (invalid response)");
    server.finish();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    drop(listener);
    let generator = GithubAppGenerator::with_client_for_tests(&config(), &keys().0,
        GithubAppGenerator::client_builder().build().unwrap(), url).unwrap();
    assert_eq!(generator.issue(&grant()).unwrap_err().message,
        "GitHub token generation failed (network error)");
}

#[test]
fn generator_issue_failure_cleanup_warning_is_sanitized_and_has_expiry() {
    let mut response = token_response("rejected-private");
    response["permissions"] = json!({"metadata":"read"});
    let server = Server::start(vec![Step::mint(response), Step::revoke(403)]);
    let error = server.generator().issue(&grant()).unwrap_err();
    assert!(error.message.starts_with(OUTSIDE_SCOPE));
    assert!(error.message.contains("GitHub token revocation failed (HTTP 403)"));
    assert!(error.message.contains("token provider expiry:"));
    assert!(!format!("{error:?}").contains("rejected-private"));
    server.finish();
}

#[test]
fn generator_fixture_reads_fragmented_requests_from_nonblocking_accepted_streams() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let sender = thread::spawn(move || {
        let mut stream = TcpStream::connect(address).unwrap();
        for fragment in [
            b"PO".as_slice(),
            b"ST /partial HTTP/1.1\r\nContent-Length: 7\r\nX-Part".as_slice(),
            b": yes\r\n\r\n{\"".as_slice(),
            b"x\":1}".as_slice(),
        ] {
            thread::sleep(Duration::from_millis(10));
            stream.write_all(fragment).unwrap();
        }
    });
    let (mut stream, _) = listener.accept().unwrap();
    // Reproduce Darwin's inheritance from the fixture's nonblocking listener,
    // including when the first header bytes have not arrived at accept time.
    stream.set_nonblocking(true).unwrap();
    let request = read_request(&mut stream);
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/partial");
    assert_eq!(request.headers["x-part"], "yes");
    assert_eq!(request.body, json!({"x":1}));
    sender.join().unwrap();
}
