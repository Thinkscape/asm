use super::*;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use asm_proto::generators::GcloudPermission::StorageRead;
use asm_proto::wire::{
    CAPABILITY_GCLOUD_ACCESS_V1, CAPABILITY_GENERATED_CREDENTIALS_V1, CAPABILITY_OPERATOR_SELECTED_GRANT_V1,
    CAPABILITY_OPERATOR_SELECTED_PROJECT_V1, HostInfo, RequestBody, RequestStatus,
};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::routing::any;
use axum::{Json, Router};
use tokio::sync::oneshot;

use crate::ffi::ManagerObserver;
use crate::generator::{GcloudConnectionConfig, gcloud::GcloudGenerator};
use crate::manager::{StartOptions, generation::GenerationState, now};
use crate::store::HostRecord;

const PROJECT: &str = "test-project";
const ALTERNATE: &str = "alternate-project";
const SEARCH: &str = "/v3/projects:search";
const ADMIN: &str = "admin@example.test";
const SUBJECT: &str = "test-subject";
const ID: &str = "112233";
const ADC: &str = r#"{"type":"authorized_user","client_id":"fixture","client_secret":"fixture","refresh_token":"fixture"}"#;
const CREATE: &str = "/v1/projects/test-project/serviceAccounts";
const PINNED: &str = "/v1/projects/test-project/serviceAccounts/112233";
const PROJECT_POLICY: &str = "/v3/projects/test-project:getIamPolicy";

struct Quiet;
impl ManagerObserver for Quiet {
    fn changed(&self, _: String) {}
}

type Hook = Box<dyn FnOnce() + Send>;

#[derive(Default)]
struct Google {
    requests: Mutex<Vec<String>>,
    email: Mutex<String>,
    conflict: AtomicBool,
    hide_alternate: AtomicBool,
    changed_subject: AtomicBool,
    before_identity: Mutex<Option<Hook>>,
    before_project_policy: Mutex<Option<Hook>>,
}

async fn google(State(g): State<Arc<Google>>, request: Request) -> (StatusCode, Json<serde_json::Value>) {
    let path = request.uri().path().to_owned();
    let method = request.method().clone();
    lock(&g.requests).push(format!("{method} {path}"));
    assert_eq!(request.headers()["authorization"], "Bearer isolated-parent");
    if path == SEARCH {
        assert!(!request.headers().contains_key("x-goog-user-project"));
    } else if path != "/v1/userinfo" {
        assert_eq!(request.headers()["x-goog-user-project"], PROJECT);
    }
    let bytes = axum::body::to_bytes(request.into_body(), 16 * 1024).await.unwrap();
    let (code, body) = match (method.as_str(), path.as_str()) {
        ("GET", "/v1/userinfo") => {
            let on_identity = lock(&g.before_identity).take();
            if let Some(on_identity) = on_identity { on_identity(); }
            (StatusCode::OK, json!({
                "sub":if g.changed_subject.load(Ordering::SeqCst) { "different-subject" } else { SUBJECT },
                "email":ADMIN, "email_verified":true
            }))
        }
        ("GET", SEARCH) => {
            let projects = if g.hide_alternate.load(Ordering::SeqCst) {
                json!([])
            } else {
                json!([{"projectId":ALTERNATE,"state":"ACTIVE"}])
            };
            (StatusCode::OK, json!({ "projects":projects }))
        }
        ("POST", CREATE) if g.conflict.load(Ordering::SeqCst) => (StatusCode::CONFLICT, json!({})),
        ("POST", CREATE) => {
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let email = gcloud_profile_email(PROJECT, body["accountId"].as_str().unwrap());
            *lock(&g.email) = email.clone();
            (StatusCode::OK, account(&email))
        }
        ("GET", PINNED) => (StatusCode::OK, account(&lock(&g.email))),
        ("POST", PROJECT_POLICY) => {
            let on_policy = lock(&g.before_project_policy).take();
            if let Some(on_policy) = on_policy { on_policy(); }
            (StatusCode::OK, json!({ "version": 3, "etag": "ACAB", "bindings": [] }))
        }
        _ => (StatusCode::NOT_FOUND, json!({})),
    };
    (code, Json(body))
}

fn account(email: &str) -> serde_json::Value {
    json!({"name":account_name(PROJECT, email), "projectId":PROJECT, "email":email, "uniqueId": ID})
}

struct Fixture {
    core: Arc<Core>,
    host: HostRecord,
    generator: String,
    google: Arc<Google>,
    clock: Arc<AtomicI64>,
    stop: Option<oneshot::Sender<()>>,
    server: Option<std::thread::JoinHandle<()>>,
    _tmp: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let google_state = Arc::new(Google::default());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = reqwest::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let (stop, stopped) = oneshot::channel();
        let server_state = google_state.clone();
        let server = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
                let router = Router::new().fallback(any(google)).with_state(server_state);
                axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), router)
                    .with_graceful_shutdown(async { let _ = stopped.await; }).await.unwrap();
            });
        });
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let dirs = crate::paths::DataDirs::create(&data, Some(tmp.path())).unwrap();
        std::fs::write(dirs.proxy.join("ca.crt"), "fixture existing ca").unwrap();
        std::fs::write(dirs.proxy.join("ca.key"), "fixture existing key").unwrap();
        let core = Core::start(data, tmp.path().join("no-proxy-binary"), Arc::new(Quiet), StartOptions {
            resume_key: Some([21; 32]),
            values_root: Some(tmp.path().to_owned()),
            settings: vec![(crate::settings::API_BIND.into(), json!("127.0.0.1")), (crate::settings::API_PORT.into(), json!(0))],
        }).unwrap();
        let clock = Arc::new(AtomicI64::new(now()));
        let read_clock = clock.clone();
        *lock(&core.generation) = GenerationState::new(Arc::new(move || read_clock.load(Ordering::SeqCst)));
        core.set_gcloud_setup_endpoint_for_test(endpoint.clone()).unwrap();
        let sdk = tmp.path().canonicalize().unwrap().join("gcloud");
        std::fs::write(&sdk, "#!/bin/sh\ncase \"$1:$2:$3\" in\nversion:*) printf '%s\\n' '{\"Google Cloud SDK\":\"582.0.0\"}' ;;\nauth:application-default:print-access-token) [ \"$#\" = 5 ] && [ -f \"$GOOGLE_APPLICATION_CREDENTIALS\" ] && printf 'isolated-parent\\n' ;;\n*) exit 1 ;;\nesac\n").unwrap();
        std::fs::set_permissions(&sdk, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config = GcloudConnectionConfig { sdk_path: sdk.to_str().unwrap().into(), account_subject: SUBJECT.into(), account_email: ADMIN.into() };
        let client = GcloudGenerator::connection_with_endpoint_for_tests(&config, ADC, &tmp.path().join("work"), endpoint).unwrap();
        let generator = new_uuid_v4();
        core.install_generator_client(GeneratorRecord { id: generator.clone(), name: "cloud".into(),
            config: GeneratorConfig::GcloudConnection(config), revision: 1, position: 1 }, Arc::new(GeneratorClient::Gcloud(client))).unwrap();
        let host = HostRecord { id: new_uuid_v4(), info: HostInfo { hostname: "isolated-host".into(), ..Default::default() },
            name: String::new(), address: "127.0.0.1".into(), paired_at: now(), last_seen: None, revoked_at: None, machine_hint: None };
        core.store.insert_host(&host, &asm_proto::crypto::sha256(host.id.as_bytes())).unwrap();
        Self { core, host, generator, google: google_state, clock, stop: Some(stop), server: Some(server), _tmp: tmp }
    }

    fn key(&self) -> GcloudProfileKey {
        GcloudProfileKey { generator_id: self.generator.clone(), account_subject: SUBJECT.into(),
            access: GcloudAccessRequest { project_id: PROJECT.into(), permissions: vec![StorageRead] } }
    }

    fn request(&self) -> String {
        self.request_with_reason("Read test storage")
    }

    fn request_with_reason(&self, reason: &str) -> String {
        self.request_with_caps(reason, &[])
    }

    fn request_with_caps(&self, reason: &str, extra: &[&str]) -> String {
        let mut capabilities = vec![CAPABILITY_GENERATED_CREDENTIALS_V1, CAPABILITY_GCLOUD_ACCESS_V1];
        capabilities.extend_from_slice(extra);
        let body: RequestBody = serde_json::from_value(json!({"kind":"get", "name":GCLOUD_TOKEN_NAME,
            "raw":true, "reason":reason, "agent":"fixture", "generation":GenerationRequest::GcloudAccess(self.key().access),
            "client_capabilities":capabilities})).unwrap();
        let state = self.core.create_request(&self.host, "127.0.0.1", body).unwrap();
        assert_eq!(state.status, RequestStatus::Pending);
        state.request_id
    }

    fn decision(&self) -> Decision {
        self.decision_with_access(self.key().access)
    }

    fn decision_with_access(&self, access: GcloudAccessRequest) -> Decision {
        Decision::ApproveGet {
            mode: crate::ffi::LeaseMode::Raw, duration_secs: Some(3600), hosts: Vec::new(),
            generation: Some(GenerationSelection {
                generator_id: self.generator.clone(), generator_revision: 1,
                grant: GenerationGrant::GcloudAccess(GcloudAccessGrant::Requested { access }),
            }.into()),
        }
    }

    fn review(&self, request: &str) -> Result<GcloudProfilePlan> {
        self.core.gcloud_profile_plan(request.to_owned(), self.decision())
    }

    fn approve(&self, request: &str, plan: &str) -> Result<()> {
        self.core.gcloud_approve_profile(request, plan, self.decision())
    }

    fn effects(&self) -> Vec<String> {
        lock(&self.google.requests).iter().filter(|p|
            (p.starts_with("POST /v1/projects/") && p.ends_with("/serviceAccounts")) || p.ends_with(":setIamPolicy"))
            .cloned().collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.core.shutdown();
        let _ = self.stop.take().unwrap().send(());
        self.server.take().unwrap().join().unwrap();
    }
}

#[test]
fn review_is_read_only_and_plans_cannot_be_replayed_replaced_or_used_after_expiry() {
    let f = Fixture::new();
    let request = f.request();
    let first = f.review(&request).unwrap();
    let next = f.review(&request).unwrap();
    assert_eq!(first.project_roles, ["roles/storage.objectViewer"]);
    assert_eq!(first.admin_principal, "user:admin@example.test");
    assert!(!first.ready);
    assert_eq!(first.expires_at, Some(f.clock.load(Ordering::SeqCst) + PLAN_LIFETIME_SECS));
    assert_ne!(first.service_account_name, next.service_account_name);
    assert_eq!(f.core.store.gcloud_profile(&f.key()).unwrap(), None);
    assert!(f.approve(&request, &first.plan_id.unwrap()).is_err());
    let next = next.plan_id.unwrap();
    f.core.gcloud_cancel_profile(next.clone()).unwrap();
    assert!(f.approve(&request, &next).is_err());
    let last = f.review(&request).unwrap().plan_id.unwrap();
    f.clock.fetch_add(PLAN_LIFETIME_SECS + 1, Ordering::SeqCst);
    assert!(f.approve(&request, &last).is_err());
    assert!(f.effects().is_empty());
}

#[test]
fn approval_stops_on_name_conflict_and_fresh_review_never_adopts_that_name() {
    let f = Fixture::new();
    f.google.conflict.store(true, Ordering::SeqCst);
    let request = f.request();
    let first = f.review(&request).unwrap();
    let plan_id = first.plan_id.unwrap();
    let error = f.approve(&request, &plan_id).unwrap_err();
    assert!(error.message.contains("did not adopt"));
    assert!(error.message.contains(&first.service_account_email));
    assert!(f.approve(&request, &plan_id).is_err());
    assert_eq!(f.effects(), [format!("POST {CREATE}")]);
    let next = f.review(&request).unwrap();
    assert_ne!(first.service_account_email, next.service_account_email);
    assert!(next.messages.iter().any(|m| m.contains(&first.service_account_email)));
}

#[test]
fn cancellation_during_policy_read_leaves_only_the_pinned_creation_and_never_writes_iam() {
    let f = Fixture::new();
    let request = f.request();
    let original = f.review(&request).unwrap();
    let other_request = f.request_with_reason("Concurrent read of test storage");
    assert_ne!(request, other_request);
    let concurrent = f.review(&other_request).unwrap().plan_id.unwrap();
    let other_decision = f.decision();
    let weak = Arc::downgrade(&f.core);
    let host_id = f.host.id.clone();
    let request_id = request.clone();
    let key = f.key();
    *lock(&f.google.before_project_policy) = Some(Box::new(move || {
        let core = weak.upgrade().unwrap();
        let persisted = core.store.gcloud_profile(&key).unwrap().unwrap();
        assert_eq!(persisted.unique_id.as_deref(), Some(ID));
        assert_eq!(persisted.phase, GcloudProfilePhase::Created);
        assert!(core.gcloud_approve_profile(&other_request, &concurrent, other_decision)
            .unwrap_err().message.contains("already in progress"));
        assert_eq!(core.cancel_request(&host_id, &request_id).unwrap().status, RequestStatus::Cancelled);
    }));
    assert!(f.approve(&request, &original.plan_id.unwrap()).is_err());
    assert_eq!(f.effects(), [format!("POST {CREATE}")]);
    assert!(f.core.store.list_leases().unwrap().is_empty());
    let next = f.review(&f.request()).unwrap();
    assert_eq!(next.service_account_email, original.service_account_email);
    assert_eq!(next.service_account_unique_id.as_deref(), Some(ID));
    assert!(!next.ready);
}

#[test]
fn read_only_review_rejects_drift_in_completed_bindings_and_revoked_host_cannot_approve() {
    let f = Fixture::new();
    let request = f.request();
    let plan = f.review(&request).unwrap().plan_id.unwrap();
    f.core.revoke_host(&f.host.id).unwrap();
    assert!(f.approve(&request, &plan).is_err());
    assert!(f.effects().is_empty());

    let f = Fixture::new();
    let (key, account_id) = (f.key(), "asm-existing-test");
    *lock(&f.google.email) = gcloud_profile_email(PROJECT, account_id);
    f.core.store.begin_gcloud_profile(&key, account_id, ADMIN, None).unwrap();
    f.core.store.record_gcloud_profile_identity(&key, account_id, ID).unwrap();
    f.core.store.mark_gcloud_profile_project_bound(&key, account_id, ID).unwrap();
    let f_request = f.request();
    assert!(f.review(&f_request).err().unwrap().message.contains("will not repair"));
    assert!(f.effects().is_empty());
}

#[test]
fn approval_rechecks_verified_subject_and_rejects_a_wrong_connection_revision() {
    let f = Fixture::new();
    let request = f.request();
    let mut wrong_revision = f.decision();
    if let Decision::ApproveGet { generation: Some(selection), .. } = &mut wrong_revision {
        selection.generator_revision = 2;
    }
    assert!(f.core.gcloud_profile_plan(request.clone(), wrong_revision.clone()).is_err());
    let id = f.review(&request).unwrap().plan_id.unwrap();
    assert!(f.core.gcloud_approve_profile(&request, &id, wrong_revision).is_err());
    let plan = f.review(&request).unwrap().plan_id.unwrap();
    f.google.changed_subject.store(true, Ordering::SeqCst);
    assert!(f.approve(&request, &plan).is_err());
    assert!(f.effects().is_empty());
    assert_eq!(f.core.store.gcloud_profile(&f.key()).unwrap(), None);
}

#[test]
fn edited_plan_cannot_write_when_connection_revision_changes_during_identity_check() {
    use asm_proto::generators::GcloudPermission::ComputeRead;
    use asm_proto::wire::CAPABILITY_OPERATOR_SELECTED_GRANT_V1;

    let f = Fixture::new();
    let body: RequestBody = serde_json::from_value(json!({
        "kind":"get", "name":GCLOUD_TOKEN_NAME, "raw":true, "reason":"Review edited access", "agent":"fixture",
        "generation":GenerationRequest::GcloudAccess(f.key().access),
        "client_capabilities":[CAPABILITY_GENERATED_CREDENTIALS_V1,CAPABILITY_GCLOUD_ACCESS_V1,CAPABILITY_OPERATOR_SELECTED_GRANT_V1]
    })).unwrap();
    let request = f.core.create_request(&f.host, "127.0.0.1", body).unwrap();
    let mut decision = f.decision();
    let Decision::ApproveGet { generation: Some(selection), .. } = &mut decision else { unreachable!() };
    let edited = GcloudAccessRequest { permissions: vec![ComputeRead], ..f.key().access };
    selection.grant = GenerationGrant::GcloudAccess(GcloudAccessGrant::Requested { access: edited.clone() }).into();
    let plan = f.core.gcloud_profile_plan(request.request_id.clone(), decision.clone()).unwrap();
    assert_eq!(plan.project_roles, ["roles/compute.viewer"]);
    let plan_id = plan.plan_id.unwrap();

    let weak = Arc::downgrade(&f.core);
    let generator = f.generator.clone();
    *lock(&f.google.before_identity) = Some(Box::new(move || {
        let core = weak.upgrade().unwrap();
        let entry = core.generators.get(&generator).unwrap();
        let client = entry.client().unwrap();
        let mut record = entry.record;
        record.revision += 1;
        core.install_generator_client(record, client).unwrap();
    }));
    assert!(f.core.gcloud_approve_profile(&request.request_id, &plan_id, decision).is_err());
    assert_eq!(f.core.request_state(&f.host.id, &request.request_id).unwrap().status, RequestStatus::Pending);
    assert!(f.effects().is_empty());
    assert_eq!(f.core.store.gcloud_profile(&GcloudProfileKey { access: edited, ..f.key() }).unwrap(), None);
    assert!(f.core.store.list_leases().unwrap().is_empty());
}

#[test]
fn approval_rejects_a_different_request_project_permission_or_delivery_before_cloud_writes() {
    use crate::ffi::LeaseMode as Mode;
    let f = Fixture::new();
    let request = f.request();
    let other = f.request_with_reason("Another operator reason for test storage");
    let plan = f.review(&request).unwrap().plan_id.unwrap();
    assert!(f.approve(&other, &plan).is_err());
    assert!(f.approve(&request, &plan).is_err(), "a mismatched attempt consumes the plan");

    let reviewed = f.decision();
    let make = |mode, duration_secs, host: &str, access| Decision::ApproveGet {
        mode, duration_secs, hosts: if host.is_empty() { Vec::new() } else { vec![host.into()] },
        generation: Some(GenerationSelection {
            generator_id: f.generator.clone(), generator_revision: 1,
            grant: GenerationGrant::GcloudAccess(GcloudAccessGrant::Requested { access }),
        }.into()),
    };
    let access = f.key().access;
    for decision in [
        make(Mode::Raw, Some(7200), "", access.clone()),
        make(Mode::Raw, Some(0), "", access.clone()),
        make(Mode::Raw, Some(3600), "storage.googleapis.com", access.clone()),
        make(Mode::Sentinel, Some(3600), "", access.clone()),
        make(Mode::Raw, Some(3600), "",
            GcloudAccessRequest { project_id: "different-project".into(), ..access.clone() }),
        make(Mode::Raw, Some(3600), "",
            GcloudAccessRequest { permissions: vec![asm_proto::generators::GcloudPermission::ComputeRead], ..access }),
    ] {
        let plan = f.core.gcloud_profile_plan(request.clone(), reviewed.clone()).unwrap().plan_id.unwrap();
        assert!(f.core.gcloud_approve_profile(&request, &plan, decision).is_err());
    }
    assert!(f.effects().is_empty());
    assert!(f.core.store.list_leases().unwrap().is_empty());
    assert_eq!(f.core.request_state(&f.host.id, &request).unwrap().status, RequestStatus::Pending);
}

#[test]
fn denial_during_identity_recheck_fences_all_cloud_writes() {
    let f = Fixture::new();
    let request = f.request();
    let plan = f.review(&request).unwrap().plan_id.unwrap();
    let weak = Arc::downgrade(&f.core);
    let request_id = request.clone();
    *lock(&f.google.before_identity) = Some(Box::new(move || {
        weak.upgrade().unwrap().resolve_request(&request_id, Decision::Deny { reason: "No longer needed".into() }).unwrap();
    }));
    assert!(f.approve(&request, &plan).is_err());
    assert_eq!(f.core.request_state(&f.host.id, &request).unwrap().status, RequestStatus::Denied);
    assert!(f.effects().is_empty());
    assert!(f.core.store.list_leases().unwrap().is_empty());
    assert!(f.approve(&request, &plan).is_err());
}

#[test]
fn alternate_project_requires_its_own_capability_evidence_and_exact_review() {
    let f = Fixture::new();
    let access = |project: &str| GcloudAccessRequest { project_id: project.into(), ..f.key().access };
    let chosen = f.decision_with_access(access(ALTERNATE));
    let legacy = f.request_with_caps("Read test storage", &[CAPABILITY_OPERATOR_SELECTED_GRANT_V1]);
    let supported = f.request_with_caps("Read test storage", &[CAPABILITY_OPERATOR_SELECTED_PROJECT_V1]);
    assert_ne!(legacy, supported, "requests with different project capabilities must not coalesce");
    let choices = |id: &str| f.core.gcloud_approval_projects(id, &f.generator, 1);
    let review = |id: &str, decision| f.core.gcloud_profile_plan(id.to_owned(), decision);
    assert!(choices(&legacy).is_err());
    assert!(review(&legacy, chosen.clone()).is_err());
    assert!(review(&supported, chosen.clone()).is_err(), "an alternate must be discovered first");

    assert_eq!(choices(&supported).unwrap(), [ALTERNATE]);
    let unrelated = f.request_with_caps("Another storage request", &[CAPABILITY_OPERATOR_SELECTED_PROJECT_V1]);
    assert!(review(&unrelated, chosen.clone()).is_err(), "catalog evidence must be tied to the request");
    assert!(review(&supported, f.decision_with_access(access("invented-project"))).is_err());
    let changed_permissions = GcloudAccessRequest {
        permissions: vec![asm_proto::generators::GcloudPermission::ComputeRead], ..access(ALTERNATE)
    };
    assert!(review(&supported, f.decision_with_access(changed_permissions)).is_err());
    assert_eq!(review(&legacy, f.decision()).unwrap().project_id, PROJECT);

    let plan = review(&supported, chosen).unwrap();
    assert_eq!(plan.project_id, ALTERNATE);
    assert!(plan.service_account_name.starts_with("projects/alternate-project/serviceAccounts/"));
    assert!(plan.service_account_email.ends_with("@alternate-project.iam.gserviceaccount.com"));
    assert_eq!(plan.project_roles, ["roles/storage.objectViewer"]);
    assert!(f.approve(&supported, &plan.plan_id.unwrap()).is_err(), "approval cannot replace the reviewed project");
    assert!(f.effects().is_empty());
    assert!(f.core.store.list_leases().unwrap().is_empty());
}

#[test]
fn alternate_project_evidence_expiring_during_approval_prevents_iam_writes() {
    let f = Fixture::new();
    let request = f.request_with_caps("Read test storage", &[CAPABILITY_OPERATOR_SELECTED_PROJECT_V1]);
    let access = GcloudAccessRequest { project_id: ALTERNATE.into(), ..f.key().access };
    let decision = f.decision_with_access(access.clone());
    f.core.gcloud_approval_projects(&request, &f.generator, 1).unwrap();
    f.clock.fetch_add(20, Ordering::SeqCst);
    let plan = f.core.gcloud_profile_plan(request.clone(), decision.clone()).unwrap();
    let expires = plan.expires_at.unwrap();
    assert!(expires < f.clock.load(Ordering::SeqCst) + PLAN_LIFETIME_SECS,
        "the IAM plan must not outlive its discovery evidence");
    let clock = f.clock.clone();
    *lock(&f.google.before_identity) = Some(Box::new(move || clock.store(expires, Ordering::SeqCst)));

    assert!(f.core.gcloud_approve_profile(&request, &plan.plan_id.unwrap(), decision.clone()).is_err());
    assert!(f.core.gcloud_profile_plan(request.clone(), decision).is_err(), "expired catalog is not new evidence");
    assert_eq!(f.core.request_state(&f.host.id, &request).unwrap().status, RequestStatus::Pending);
    assert_eq!(f.core.store.gcloud_profile(&GcloudProfileKey { access, ..f.key() }).unwrap(), None);
    assert!(f.effects().is_empty());
    assert!(f.core.store.list_leases().unwrap().is_empty());
}

#[test]
fn a_new_catalog_that_omits_the_alternate_invalidates_the_existing_plan() {
    let f = Fixture::new();
    let request = f.request_with_caps("Read test storage", &[CAPABILITY_OPERATOR_SELECTED_PROJECT_V1]);
    let access = GcloudAccessRequest { project_id: ALTERNATE.into(), ..f.key().access };
    let decision = f.decision_with_access(access.clone());
    let discover = || f.core.gcloud_approval_projects(&request, &f.generator, 1);
    assert_eq!(discover().unwrap(), [ALTERNATE]);
    let reviewed = f.core.gcloud_profile_plan(request.clone(), decision.clone()).unwrap();
    f.google.hide_alternate.store(true, Ordering::SeqCst);
    assert!(discover().unwrap().is_empty());
    assert!(f.core.gcloud_approve_profile(&request, &reviewed.plan_id.unwrap(), decision).is_err());
    assert_eq!(f.review(&request).unwrap().project_id, PROJECT, "the original needs no catalog evidence");
    assert_eq!(f.core.store.gcloud_profile(&GcloudProfileKey { access, ..f.key() }).unwrap(), None);
    assert!(f.effects().is_empty());
    assert!(f.core.store.list_leases().unwrap().is_empty());
}

#[test]
fn a_cancelled_request_does_not_receive_in_flight_project_evidence() {
    let f = Fixture::new();
    let request = f.request_with_caps("Read test storage", &[CAPABILITY_OPERATOR_SELECTED_PROJECT_V1]);
    let weak = Arc::downgrade(&f.core);
    let request_id = request.clone();
    let host_id = f.host.id.clone();
    *lock(&f.google.before_identity) = Some(Box::new(move || {
        let state = weak.upgrade().unwrap().cancel_request(&host_id, &request_id).unwrap();
        assert_eq!(state.status, RequestStatus::Cancelled);
    }));
    assert!(f.core.gcloud_approval_projects(&request, &f.generator, 1).is_err());
    let next = f.request_with_caps("Read test storage", &[CAPABILITY_OPERATOR_SELECTED_PROJECT_V1]);
    let access = GcloudAccessRequest { project_id: ALTERNATE.into(), ..f.key().access };
    assert!(f.core.gcloud_profile_plan(next, f.decision_with_access(access)).is_err());
    assert!(f.effects().is_empty());
}
