use super::*;
use asm_proto::error::ErrorCode;
use asm_proto::generators::GcloudPermission::{ComputeRead, StorageRead};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

const TOKEN: &str = "test-parent-token";
const PROJECT: &str = "test-project";
const ACCOUNT_ID: &str = "asm-profile-test";
const ACCOUNT_EMAIL: &str = "asm-profile-test@test-project.iam.gserviceaccount.com";
const UNIQUE_ID: &str = "102030405060708090001";
const ACCOUNT_NAME: &str = "projects/test-project/serviceAccounts/102030405060708090001";
const ACCOUNT_MEMBER: &str = "serviceAccount:asm-profile-test@test-project.iam.gserviceaccount.com";
const DELETED_MEMBER: &str = "deleted:serviceAccount:asm-profile-test@test-project.iam.gserviceaccount.com?uid=102030405060708090001";
const HUMAN: &str = "operator@example.com";
const HUMAN_MEMBER: &str = "user:operator@example.com";
const SUBJECT: &str = "123456789012345678901";
const STORAGE: &str = "roles/storage.objectViewer";
const COMPUTE: &str = "roles/compute.viewer";
const CREATE_PATH: &str = "/v1/projects/test-project/serviceAccounts";
const ACCOUNT_PATH: &str = "/v1/projects/test-project/serviceAccounts/102030405060708090001";
const GET_ACCOUNT_POLICY_PATH: &str = "/v1/projects/test-project/serviceAccounts/102030405060708090001:getIamPolicy?options.requestedPolicyVersion=3";
const SET_ACCOUNT_POLICY_PATH: &str = "/v1/projects/test-project/serviceAccounts/102030405060708090001:setIamPolicy";
const GET_PROJECT_POLICY_PATH: &str = "/v3/projects/test-project:getIamPolicy";
const SET_PROJECT_POLICY_PATH: &str = "/v3/projects/test-project:setIamPolicy";
const USERINFO_PATH: &str = "/v1/userinfo";

struct Exchange {
    method: &'static str,
    path: &'static str,
    body: Option<Value>,
    status: u16,
    response: Value,
}

impl Exchange {
    fn get(path: &'static str, response: Value) -> Self {
        Self { method: "GET", path, body: None, status: 200, response }
    }

    fn post(path: &'static str, body: Option<Value>, response: Value) -> Self {
        Self { method: "POST", path, body, status: 200, response }
    }

    fn create(response: Value) -> Self {
        Self::post(CREATE_PATH, Some(json!({
            "accountId": ACCOUNT_ID,
            "serviceAccount": {"displayName": "ASM access profile"},
        })), response)
    }

    fn account() -> Self {
        Self::get(ACCOUNT_PATH, account())
    }

    fn delete(status: u16, response: Value) -> Self {
        Self { method: "DELETE", path: ACCOUNT_PATH, body: None, status, response }
    }

    fn userinfo(subject: &str) -> Self {
        Self::get(USERINFO_PATH, json!({"email": HUMAN, "sub": subject, "email_verified": true}))
    }

    fn get_project_policy(response: Value) -> Self {
        Self::post(GET_PROJECT_POLICY_PATH, Some(json!({"options": {"requestedPolicyVersion": 3}})), response)
    }

    fn get_account_policy(response: Value) -> Self {
        Self::post(GET_ACCOUNT_POLICY_PATH, None, response)
    }

    fn set_policy(path: &'static str, policy: Value, response: Value) -> Self {
        Self::post(path, Some(json!({"policy": policy, "updateMask": "bindings,etag"})), response)
    }
}

fn loopback(steps: Vec<Exchange>, run: impl FnOnce(&GcloudHttp)) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    let (done, finished) = mpsc::channel();
    let server = thread::spawn(move || {
        for exchange in steps {
            let mut stream = accept(&listener, &finished).expect("expected Google HTTP request");
            exchange_request(&exchange, &mut stream);
            let body = exchange.response.to_string();
            write!(stream,
                "HTTP/1.1 {} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                exchange.status, body.len(),
            ).unwrap();
        }
        // Keep listening until the operation returns to catch retries/extra writes.
        assert!(accept(&listener, &finished).is_none(), "unexpected Google HTTP request");
    });
    run(&GcloudHttp::with_test_endpoint(endpoint).unwrap());
    let _ = done.send(());
    server.join().unwrap();
}

fn accept(listener: &TcpListener, finished: &Receiver<()>) -> Option<TcpStream> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                return Some(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if !matches!(finished.try_recv(), Err(mpsc::TryRecvError::Empty)) {
                    return None;
                }
                assert!(Instant::now() < deadline, "timed out waiting for a Google HTTP request");
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("loopback request failed: {error}"),
        }
    }
}

fn exchange_request(exchange: &Exchange, stream: &mut TcpStream) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    assert_ne!(reader.read_line(&mut line).unwrap(), 0);
    let mut words = line.split_ascii_whitespace();
    assert_eq!(words.next(), Some(exchange.method));
    assert_eq!(words.next(), Some(exchange.path));
    let mut content_length = None;
    let mut bearer = false;
    let mut quota = false;
    loop {
        line.clear();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0);
        if line == "\r\n" { break; }
        let (key, value) = line.split_once(':').unwrap();
        match key.to_ascii_lowercase().as_str() {
            "authorization" => {
                assert_eq!(value.trim(), format!("Bearer {TOKEN}"));
                bearer = true;
            }
            "x-goog-user-project" => {
                assert_eq!(value.trim(), PROJECT);
                quota = true;
            }
            "content-length" => content_length = Some(value.trim().parse::<usize>().unwrap()),
            _ => {}
        }
    }
    assert!(bearer);
    assert_eq!(quota, exchange.path != USERINFO_PATH);
    if let Some(expected) = &exchange.body {
        let mut bytes = vec![0; content_length.unwrap()];
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(&serde_json::from_slice::<Value>(&bytes).unwrap(), expected);
    } else if exchange.method == "POST" {
        // Google's front end rejects a bodyless POST without Content-Length (HTTP 411).
        assert_eq!(content_length, Some(0), "POST {} must send Content-Length: 0", exchange.path);
    } else {
        assert_eq!(content_length.unwrap_or(0), 0);
    }
}

fn access() -> GcloudAccessRequest {
    let mut access = GcloudAccessRequest { project_id: PROJECT.into(), permissions: vec![StorageRead, ComputeRead] };
    access.canonicalize().unwrap();
    access
}

fn identity() -> GcloudIdentity {
    GcloudIdentity { subject: SUBJECT.into(), email: HUMAN.into() }
}

fn account() -> Value {
    json!({"name": ACCOUNT_NAME, "projectId": PROJECT, "uniqueId": UNIQUE_ID, "email": ACCOUNT_EMAIL})
}

fn binding(role: &str, member: &str) -> Value {
    json!({"role": role, "members": [member]})
}

fn project_policy() -> Value {
    json!({"etag":"AQAB", "version":1, "bindings":[binding(STORAGE, ACCOUNT_MEMBER), binding(COMPUTE, ACCOUNT_MEMBER)]})
}

fn account_policy() -> Value {
    json!({"etag":"AQAB", "version":1, "bindings":[binding(TOKEN_CREATOR, HUMAN_MEMBER)]})
}

fn not_found() -> Value {
    json!({"error": {"code": 404, "status": "NOT_FOUND", "message": "Service account not found"}})
}

#[test]
fn provision_and_verify_use_only_the_planned_account_roles_and_human() {
    let project = json!({
        "etag": "ACAB", "version": 3,
        "auditConfigs": [{"service": "storage.googleapis.com", "auditLogConfigs": [
            {"logType": "DATA_READ", "exemptedMembers": ["user:audit@example.com"], "futureAudit": true},
        ]}],
        "futurePolicy": {"opaque": true},
        "bindings": [
            {"role": "roles/owner", "members": ["user:owner@example.com"]},
            {"role": STORAGE, "members": ["group:readers@example.com"], "futureBinding": 42},
            {"role": COMPUTE, "members": ["user:other@example.com"],
             "condition": {"title": "conditional elsewhere", "expression": "true", "futureExpr": 42}},
        ],
    });
    let mut project_write = project.clone();
    project_write["bindings"][1]["members"].as_array_mut().unwrap().push(json!(ACCOUNT_MEMBER));
    project_write["bindings"].as_array_mut().unwrap().push(binding(COMPUTE, ACCOUNT_MEMBER));
    let mut project_result = project_write.clone();
    project_result["etag"] = json!("AQAB");

    let account_write = json!({"etag": "ACAB", "version": 3, "bindings": [binding(TOKEN_CREATOR, HUMAN_MEMBER)]});
    loopback(vec![
        Exchange::create(account()),
        Exchange::get_project_policy(project), Exchange::account(),
        Exchange::set_policy(SET_PROJECT_POLICY_PATH, project_write, project_result.clone()),
        Exchange::get_account_policy(json!({"etag": "ACAB"})), Exchange::account(), Exchange::userinfo(SUBJECT),
        Exchange::set_policy(SET_ACCOUNT_POLICY_PATH, account_write, account_policy()),
        Exchange::account(), Exchange::get_project_policy(project_result), Exchange::get_account_policy(account_policy()),
    ], |http| {
        let created = http.create_profile_account(TOKEN, PROJECT, ACCOUNT_ID).unwrap();
        assert_eq!(created.unique_id, UNIQUE_ID);
        assert_eq!(created.email, ACCOUNT_EMAIL);
        let mut checked = 0;
        http.apply_profile_project_roles(TOKEN, &access(), &created.unique_id, &created.email, || {
            checked += 1;
            Ok(())
        }).unwrap();
        http.apply_profile_token_creator(TOKEN, PROJECT, &created.unique_id, &created.email, &identity(), || {
            checked += 1;
            Ok(())
        }).unwrap();
        assert_eq!(checked, 2);
        http.verify_profile_ready(TOKEN, &access(), &created.unique_id, &created.email, &identity()).unwrap();
    });
}

#[test]
fn token_creator_write_preserves_unrelated_account_bindings() {
    let prior_policy = json!({
        "etag": "ACAB", "version": 3,
        "bindings": [
            {"role": TOKEN_CREATOR, "members": ["group:platform@example.com"], "condition": {"expression": "true"}},
            {"role": "roles/iam.serviceAccountUser", "members": ["user:deploy@example.com"]},
        ],
        "futurePolicy": "unchanged",
    });
    let mut write = prior_policy.clone();
    write["bindings"].as_array_mut().unwrap().push(binding(TOKEN_CREATOR, HUMAN_MEMBER));
    let mut result = write.clone();
    result["etag"] = json!("AQAB");
    loopback(vec![
        Exchange::get_account_policy(prior_policy), Exchange::account(), Exchange::userinfo(SUBJECT),
        Exchange::set_policy(SET_ACCOUNT_POLICY_PATH, write, result),
    ], |http| {
        http.apply_profile_token_creator(TOKEN, PROJECT, UNIQUE_ID, ACCOUNT_EMAIL, &identity(), || Ok(())).unwrap();
    });
}

#[test]
fn refuses_unapproved_project_account_and_invalid_human_before_requests() {
    let mut other_project = access();
    other_project.project_id = "other-project".into();
    let mut wrong_human = identity();
    wrong_human.email = ACCOUNT_EMAIL.into();
    loopback(vec![], |http| {
        assert_eq!(http.create_profile_account(TOKEN, PROJECT, "../new-account").unwrap_err().code, ErrorCode::Invalid);
        assert_eq!(http.verify_profile_account(TOKEN, PROJECT, "102030/keys", ACCOUNT_EMAIL).unwrap_err().code, ErrorCode::Invalid);
        assert_eq!(http.apply_profile_project_roles(TOKEN, &other_project, UNIQUE_ID, ACCOUNT_EMAIL, || {
            panic!("profile account must belong to the approved project")
        }).unwrap_err().code, ErrorCode::Invalid);
        assert_eq!(http.apply_profile_token_creator(TOKEN, PROJECT, UNIQUE_ID, ACCOUNT_EMAIL, &wrong_human, || {
            panic!("Token Creator must go only to the verified Google user")
        }).unwrap_err().code, ErrorCode::Invalid);
    });
}

#[test]
fn does_not_adopt_conflicts_or_accept_an_unconfirmed_account() {
    let mut wrong_identity = account();
    wrong_identity["email"] = json!("someone-else@test-project.iam.gserviceaccount.com");
    let mut wrong_project = account();
    wrong_project["projectId"] = json!("other-project");
    let mut invalid_id = account();
    invalid_id["uniqueId"] = json!("");
    let mut wrong_name = account();
    wrong_name["name"] = json!("projects/other-project/serviceAccounts/102030405060708090001");
    for step in [
        Exchange { status: 409, ..Exchange::create(json!({"error": TOKEN})) },
        Exchange::create(wrong_identity), Exchange::create(wrong_project),
        Exchange::create(invalid_id), Exchange::create(wrong_name),
    ] {
        loopback(vec![step], |http| {
            let error = http.create_profile_account(TOKEN, PROJECT, ACCOUNT_ID).err().unwrap();
            assert_eq!(error.code, ErrorCode::VaultUnavailable);
            assert!(!error.message.contains(TOKEN));
        });
    }
}

#[test]
fn account_verification_rejects_disabled_and_recreated_identities() {
    let mut disabled = account();
    disabled["disabled"] = json!(true);
    let mut recreated = account();
    recreated["uniqueId"] = json!("102030405060708090009");
    for response in [disabled, recreated] {
        loopback(vec![Exchange::get(ACCOUNT_PATH, response)], |http| {
            assert!(http.verify_profile_account(TOKEN, PROJECT, UNIQUE_ID, ACCOUNT_EMAIL).is_err());
        });
    }
}

#[test]
fn resumes_missing_approved_bindings_and_noops_after_a_successful_write() {
    let partial = json!({"etag":"ACAB", "version":1, "bindings":[binding(STORAGE, ACCOUNT_MEMBER)]});
    let mut update = project_policy();
    update["etag"] = json!("ACAB");
    update["version"] = json!(3);
    let mut previous_account_policy = account_policy();
    previous_account_policy["version"] = json!(3);
    previous_account_policy["bindings"].as_array_mut().unwrap().push(json!({
        "role": TOKEN_CREATOR, "members": ["group:other@example.com"], "condition": {"expression": "true"},
    }));
    loopback(vec![
        Exchange::account(), Exchange::get_project_policy(partial.clone()),
        Exchange::get_project_policy(partial), Exchange::account(),
        Exchange::set_policy(SET_PROJECT_POLICY_PATH, update, project_policy()),
        Exchange::get_project_policy(project_policy()), Exchange::account(),
        Exchange::get_account_policy(previous_account_policy.clone()), Exchange::account(),
        Exchange::account(), Exchange::get_account_policy(previous_account_policy),
    ], |http| {
        assert!(http.verify_profile_project_roles(TOKEN, &access(), UNIQUE_ID, ACCOUNT_EMAIL)
            .unwrap_err().message.contains("missing an approved"));
        http.apply_profile_project_roles(TOKEN, &access(), UNIQUE_ID, ACCOUNT_EMAIL, || Ok(())).unwrap();
        http.apply_profile_project_roles(TOKEN, &access(), UNIQUE_ID, ACCOUNT_EMAIL, || panic!("exact project policy must not be rewritten")).unwrap();
        http.apply_profile_token_creator(TOKEN, PROJECT, UNIQUE_ID, ACCOUNT_EMAIL, &identity(), || panic!("exact Token Creator must not be rewritten")).unwrap();
        http.verify_profile_token_creator(TOKEN, PROJECT, UNIQUE_ID, ACCOUNT_EMAIL, &identity()).unwrap();
    });
}

#[test]
fn fails_closed_on_extra_conditional_or_duplicate_direct_project_role() {
    let conditional = json!({"role": STORAGE, "members": [ACCOUNT_MEMBER], "condition": {"expression": "true"}});
    for drift in [
        binding("roles/editor", ACCOUNT_MEMBER), conditional, binding(STORAGE, ACCOUNT_MEMBER),
        binding(COMPUTE, &ACCOUNT_MEMBER.to_ascii_uppercase()),
        binding("roles/owner", &format!("deleted:{ACCOUNT_MEMBER}?uid={UNIQUE_ID}")),
    ] {
        let mut current = project_policy();
        current["version"] = json!(3);
        current["bindings"].as_array_mut().unwrap().push(drift);
        loopback(vec![
            Exchange::account(), Exchange::get_project_policy(current.clone()),
            Exchange::get_project_policy(current),
        ], |http| {
            let error = http.verify_profile_project_roles(TOKEN, &access(), UNIQUE_ID, ACCOUNT_EMAIL).unwrap_err();
            assert!(error.message.contains("unexpected, duplicate, or conditional"));
            assert!(http.apply_profile_project_roles(TOKEN, &access(), UNIQUE_ID, ACCOUNT_EMAIL, || {
                panic!("project drift cannot be repaired by a provisioning retry")
            }).is_err());
        });
    }
}

#[test]
fn malformed_or_unversioned_conditional_policies_are_never_written() {
    for bad in [
        json!({}),
        json!({"etag": ""}),
        json!({"etag": "not valid!"}),
        json!({"etag": "ACAB", "bindings": null}),
        json!({"etag": "ACAB", "version": 2}),
        json!({"etag": "ACAB", "version": 3, "auditConfigs": {}}),
        json!({"etag": "ACAB", "version": 1, "bindings": [binding("roles/viewer_withcond_hash", "user:other@example.com")]}),
        json!({"etag": "ACAB", "version": 3, "bindings": [{"role": STORAGE, "members":[ACCOUNT_MEMBER], "condition":null}]}),
        json!({"etag": "ACAB", "version": 1, "bindings": [{"role": STORAGE, "members":["user:other@example.com"], "condition":{"expression":"true"}}]}),
    ] {
        loopback(vec![Exchange::get_project_policy(bad)], |http| {
            assert!(http.apply_profile_project_roles(TOKEN, &access(), UNIQUE_ID, ACCOUNT_EMAIL, || panic!("malformed IAM policy must not be written"))
                .unwrap_err().message.contains("malformed or incomplete"));
        });
    }
}

#[test]
fn missing_etag_or_conditional_human_grant_blocks_token_creator_write() {
    let conditional = json!({"version":3, "etag":"ACAB", "bindings":[{
        "role": TOKEN_CREATOR, "members":[HUMAN_MEMBER], "condition":{"expression":"true"},
    }]});
    for bad in [json!({}), conditional] {
        loopback(vec![Exchange::get_account_policy(bad)], |http| {
            assert!(http.apply_profile_token_creator(TOKEN, PROJECT, UNIQUE_ID, ACCOUNT_EMAIL, &identity(), || {
                panic!("cannot broaden a conditional role or overwrite a policy without an etag")
            }).is_err());
        });
    }
}

#[test]
fn stale_confirmation_or_changed_subject_stops_before_any_policy_set() {
    loopback(vec![Exchange::get_project_policy(json!({"etag":"ACAB"})), Exchange::account()], |http| {
        let error = http.apply_profile_project_roles(TOKEN, &access(), UNIQUE_ID, ACCOUNT_EMAIL, || {
            Err(CoreError::invalid("stale confirmation"))
        }).unwrap_err();
        assert_eq!(error.message, "stale confirmation");
    });
    loopback(vec![Exchange::get_account_policy(json!({"etag":"ACAB"})), Exchange::account(), Exchange::userinfo("another-subject")], |http| {
        let error = http.apply_profile_token_creator(TOKEN, PROJECT, UNIQUE_ID, ACCOUNT_EMAIL, &identity(), || {
            panic!("changed subject cannot reach a write")
        }).unwrap_err();
        assert_eq!(error.code, ErrorCode::Unauthorized);
    });
}

#[test]
fn no_stale_policy_retry_and_no_success_from_incomplete_write_ack() {
    let mut expected_write = project_policy();
    expected_write["etag"] = json!("ACAB");
    expected_write["version"] = json!(3);
    // Follow shared canonical permission order rather than relying on struct order.
    expected_write["bindings"] = json!(access().permissions.iter().map(|p| binding(p.role(), ACCOUNT_MEMBER)).collect::<Vec<_>>());
    for (status, response) in [
        (409, json!({"error": TOKEN})),
        (412, json!({"error": TOKEN})),
        (200, account_policy()),
        (401, json!({"error": TOKEN})),
    ] {
        loopback(vec![
            Exchange::get_project_policy(json!({"etag":"ACAB"})), Exchange::account(),
            Exchange { status, ..Exchange::set_policy(SET_PROJECT_POLICY_PATH, expected_write.clone(), response) },
        ], |http| {
            let error = http.apply_profile_project_roles(TOKEN, &access(), UNIQUE_ID, ACCOUNT_EMAIL, || Ok(())).unwrap_err();
            assert_eq!(error.code, if status == 401 { ErrorCode::Unauthorized } else { ErrorCode::VaultUnavailable });
            assert!(!error.message.contains(TOKEN));
        });
    }
}

#[test]
fn failed_policy_write_reports_googles_message_but_never_an_echoed_token() {
    let mut expected_write = project_policy();
    expected_write["etag"] = json!("ACAB");
    expected_write["version"] = json!(3);
    expected_write["bindings"] = json!(access().permissions.iter().map(|p| binding(p.role(), ACCOUNT_MEMBER)).collect::<Vec<_>>());
    let explained = json!({"error": {"code": 400, "status": "INVALID_ARGUMENT",
        "message": "Service account asm-profile-test@test-project.iam.gserviceaccount.com does not exist.\nRetry later."}});
    let echoed = json!({"error": {"code": 400, "status": "INVALID_ARGUMENT", "message": format!("bad token {TOKEN}")}});
    for (response, expected) in [
        (explained, "HTTP 400; Google: INVALID_ARGUMENT: Service account asm-profile-test@test-project.iam.gserviceaccount.com does not exist. Retry later."),
        (echoed, "(HTTP 400)"),
    ] {
        loopback(vec![
            Exchange::get_project_policy(json!({"etag":"ACAB"})), Exchange::account(),
            Exchange { status: 400, ..Exchange::set_policy(SET_PROJECT_POLICY_PATH, expected_write.clone(), response) },
        ], |http| {
            let error = http.apply_profile_project_roles(TOKEN, &access(), UNIQUE_ID, ACCOUNT_EMAIL, || Ok(())).unwrap_err();
            assert_eq!(error.code, ErrorCode::VaultUnavailable);
            assert!(error.message.contains(expected), "{}", error.message);
            assert!(!error.message.contains(TOKEN));
        });
    }
}

#[test]
fn deletes_disabled_account_by_uid_and_prunes_only_its_approved_unconditional_deleted_bindings() {
    const OTHER_UID: &str = "deleted:serviceAccount:asm-profile-test@test-project.iam.gserviceaccount.com?uid=102030405060708090009";
    let mut disabled = account();
    disabled["disabled"] = json!(true);
    let project = json!({
        "etag": "ACAB", "version": 3,
        "auditConfigs": [{"service": "storage.googleapis.com", "auditLogConfigs": [{"logType":"DATA_READ"}]}],
        "futurePolicy": {"opaque": true},
        "bindings": [
            {"role": STORAGE, "members":[DELETED_MEMBER, ACCOUNT_MEMBER, OTHER_UID, "user:reader@example.com"], "futureBinding": 42},
            binding(COMPUTE, DELETED_MEMBER),
            {"role": COMPUTE, "members":[DELETED_MEMBER], "condition":{"title": "externally managed", "expression":"true"}},
            binding("roles/owner", DELETED_MEMBER),
        ],
    });
    let mut written = project.clone();
    let bindings = written["bindings"].as_array_mut().unwrap();
    bindings[0]["members"] = json!([ACCOUNT_MEMBER, OTHER_UID, "user:reader@example.com"]);
    bindings.remove(1);
    let mut applied = written.clone();
    applied["etag"] = json!("AQAB");
    loopback(vec![
        Exchange::userinfo(SUBJECT),
        Exchange::get(ACCOUNT_PATH, disabled),
        Exchange::delete(200, json!({})),
        Exchange::get_project_policy(project),
        Exchange::userinfo(SUBJECT),
        Exchange::set_policy(SET_PROJECT_POLICY_PATH, written, applied),
    ], |http| {
        let mut checks = 0;
        http.delete_profile_account(TOKEN, &access(), UNIQUE_ID, ACCOUNT_EMAIL, &identity(), || {
            checks += 1;
            Ok(())
        }).unwrap();
        assert_eq!(checks, 2);
    });
}

#[test]
fn known_absence_is_idempotent_without_touching_a_recycled_email() {
    for already_absent in [true, false] {
        let mut steps = vec![Exchange::userinfo(SUBJECT)];
        if already_absent {
            steps.push(Exchange { status: 404, ..Exchange::get(ACCOUNT_PATH, not_found()) });
        } else {
            steps.extend([Exchange::account(), Exchange::delete(404, not_found())]);
        }
        steps.push(Exchange::get_project_policy(project_policy()));
        loopback(steps, |http| {
            let mut deletes = 0;
            http.delete_profile_account(TOKEN, &access(), UNIQUE_ID, ACCOUNT_EMAIL, &identity(), || {
                deletes += 1;
                Ok(())
            }).unwrap();
            assert_eq!(deletes, if already_absent { 0 } else { 1 });
        });
    }
}

#[test]
fn never_deletes_on_a_mismatched_parent_or_account() {
    for parent in [
        Exchange::userinfo("other-subject"),
        Exchange::get(USERINFO_PATH, json!({"sub": SUBJECT, "email": "renamed@example.com", "email_verified": true})),
    ] {
        loopback(vec![parent], |http| {
            let error = http.delete_profile_account(TOKEN, &access(), UNIQUE_ID, ACCOUNT_EMAIL, &identity(), || {
                panic!("a changed parent cannot reach deletion")
            }).unwrap_err();
            assert_eq!(error.code, ErrorCode::Unauthorized);
        });
    }
    for (field, value) in [
        ("uniqueId", "102030405060708090009"),
        ("email", "asm-other@test-project.iam.gserviceaccount.com"),
        ("projectId", "other-project"),
        ("name", "projects/other-project/serviceAccounts/102030405060708090001"),
    ] {
        let mut different_account = account();
        different_account[field] = json!(value);
        loopback(vec![Exchange::userinfo(SUBJECT), Exchange::get(ACCOUNT_PATH, different_account)], |http| {
            let error = http.delete_profile_account(TOKEN, &access(), UNIQUE_ID, ACCOUNT_EMAIL, &identity(), || {
                panic!("a different account cannot reach deletion")
            }).unwrap_err();
            assert!(error.message.contains("did not confirm the planned service account identity"));
        });
    }
}

#[test]
fn deletion_does_not_treat_forbidden_or_malformed_verification_as_absence() {
    for (status, response, message) in [
        (403, json!({"error": TOKEN}), "iam.serviceAccounts.get"),
        (404, json!({}), "malformed or incomplete"),
        (200, json!({"email": ACCOUNT_EMAIL}), "malformed or incomplete"),
        (503, json!({"error": TOKEN}), "HTTP 503"),
    ] {
        loopback(vec![
            Exchange::userinfo(SUBJECT), Exchange { status, ..Exchange::get(ACCOUNT_PATH, response) },
        ], |http| {
            let error = http.delete_profile_account(TOKEN, &access(), UNIQUE_ID, ACCOUNT_EMAIL, &identity(), || {
                panic!("unconfirmed account state cannot reach deletion")
            }).unwrap_err();
            assert!(error.message.contains(message));
            assert!(!error.message.contains(TOKEN));
        });
    }
}

#[test]
fn deletion_does_not_retry_or_clean_policy_after_an_unconfirmed_delete() {
    for (status, response, message) in [
        (403, json!({"error": TOKEN}), "iam.serviceAccounts.delete"),
        (404, json!({"error": {"code": 404, "status": "PERMISSION_DENIED", "message": TOKEN}}), "malformed or incomplete"),
        (404, json!({"error": {"code": 403, "status": "NOT_FOUND", "message": TOKEN}}), "malformed or incomplete"),
        (200, json!({"error": TOKEN}), "malformed or incomplete"),
        (503, json!({"error": TOKEN}), "HTTP 503"),
    ] {
        loopback(vec![Exchange::userinfo(SUBJECT), Exchange::account(), Exchange::delete(status, response)], |http| {
            let error = http.delete_profile_account(TOKEN, &access(), UNIQUE_ID, ACCOUNT_EMAIL, &identity(), || Ok(())).unwrap_err();
            assert!(error.message.contains(message));
            assert!(!error.message.contains(TOKEN));
        });
    }
}

#[test]
fn rechecks_local_authority_before_each_effect_and_parent_before_policy_write() {
    loopback(vec![Exchange::userinfo(SUBJECT), Exchange::account()], |http| {
        let error = http.delete_profile_account(TOKEN, &access(), UNIQUE_ID, ACCOUNT_EMAIL, &identity(), || {
            Err(CoreError::invalid("stale confirmation before delete"))
        }).unwrap_err();
        assert_eq!(error.message, "stale confirmation before delete");
    });
    let policy = json!({"etag": "ACAB", "bindings": [binding(STORAGE, DELETED_MEMBER)]});
    for parent in [SUBJECT, "other-subject"] {
        loopback(vec![
            Exchange::userinfo(SUBJECT), Exchange::account(), Exchange::delete(200, json!({})),
            Exchange::get_project_policy(policy.clone()), Exchange::userinfo(parent),
        ], |http| {
            let mut checks = 0;
            let error = http.delete_profile_account(TOKEN, &access(), UNIQUE_ID, ACCOUNT_EMAIL, &identity(), || {
                checks += 1;
                if checks == 2 { return Err(CoreError::invalid("stale confirmation before policy write")); }
                Ok(())
            }).unwrap_err();
            if parent == SUBJECT {
                assert_eq!(checks, 2);
                assert_eq!(error.message, "stale confirmation before policy write");
            } else {
                assert_eq!(checks, 1);
                assert_eq!(error.code, ErrorCode::Unauthorized);
            }
        });
    }
}

#[test]
fn absent_account_retries_only_the_uid_specific_policy_cleanup_and_requires_positive_ack() {
    let policy = json!({"etag": "ACAB", "bindings": [binding(STORAGE, DELETED_MEMBER)]});
    let expected_write = json!({"etag": "ACAB", "version": 3});
    for (status, response, message) in [
        (412, json!({"error": TOKEN}), Some("no retry was attempted")),
        (200, policy.clone(), Some("did not confirm removal")),
        (200, json!({"etag": "AQAB"}), None),
    ] {
        loopback(vec![
            Exchange::userinfo(SUBJECT), Exchange { status: 404, ..Exchange::get(ACCOUNT_PATH, not_found()) },
            Exchange::get_project_policy(policy.clone()), Exchange::userinfo(SUBJECT),
            Exchange { status, ..Exchange::set_policy(SET_PROJECT_POLICY_PATH, expected_write.clone(), response) },
        ], |http| {
            let result = http.delete_profile_account(TOKEN, &access(), UNIQUE_ID, ACCOUNT_EMAIL, &identity(), || Ok(()));
            if let Some(message) = message {
                let error = result.unwrap_err();
                assert!(error.message.contains(message));
                assert!(!error.message.contains(TOKEN));
            } else {
                result.unwrap();
            }
        });
    }
}
