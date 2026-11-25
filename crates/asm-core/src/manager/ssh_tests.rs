//! Real manager and store with a fake target runner. No network, Keychain or host changes.
use super::*;
use std::collections::VecDeque;
use std::sync::atomic::AtomicI64;
use std::sync::mpsc;
use std::time::Instant;

use asm_proto::ErrorCode;
use asm_proto::ssh::Reader;
use asm_proto::wire::HostInfo;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ssh_key::Certificate;

use crate::manager::{StartOptions, now};
use crate::ssh::userauth::tests::{hostbound_payload, payload};
use crate::store::HostRecord;

struct Quiet;
impl ffi::ManagerObserver for Quiet {
    fn changed(&self, _: String) {}
}

type Answer = std::result::Result<RemoteOutput, RemoteError>;
type Handler = Arc<dyn Fn(&Call) -> Answer + Send + Sync>;

#[derive(Debug, Clone)]
struct Call {
    target_id: String,
    auth: RemoteAuth,
    stdin: String,
    /// The certificate a certificate run found in its directory.
    cert: Option<String>,
}

/// Answers from `handler` when set, else from `answers`, else `asm-end-ok 0`. A
/// `route` error refuses every target's route.
#[derive(Default)]
struct FakeRemote {
    calls: Mutex<Vec<Call>>,
    answers: Mutex<VecDeque<Answer>>,
    handler: Mutex<Option<Handler>>,
    route: Mutex<Option<RemoteError>>,
}

impl FakeRemote {
    fn answer(&self, answer: Answer) {
        lock(&self.answers).push_back(answer);
    }

    fn calls(&self) -> Vec<Call> {
        lock(&self.calls).clone()
    }
}

impl SshRemote for FakeRemote {
    fn run(&self, target: &SshTargetRecord, auth: &RemoteAuth, stdin: &str, _timeout: Duration) -> Answer {
        let cert = match auth {
            RemoteAuth::Certificate { dir, .. } => std::fs::read_to_string(dir.join("id-cert.pub")).ok(),
            RemoteAuth::Operator { .. } => None,
        };
        let call = Call { target_id: target.id.clone(), auth: auth.clone(), stdin: stdin.to_owned(), cert };
        lock(&self.calls).push(call.clone());
        let handler = lock(&self.handler).clone();
        if let Some(handler) = handler {
            return handler(&call);
        }
        lock(&self.answers).pop_front().unwrap_or_else(|| out(0, "asm-end-ok 0\n", ""))
    }

    fn check_route(&self, _target: &SshTargetRecord, _dir: &Path) -> std::result::Result<(), RemoteError> {
        lock(&self.route).clone().map_or(Ok(()), Err)
    }
}

fn out(status: i32, stdout: &str, stderr: &str) -> Answer {
    Ok(RemoteOutput { status, stdout: stdout.into(), stderr: stderr.into() })
}

fn host_key() -> String {
    SshKey::generate().openssh_line()
}

struct Fixture {
    core: Arc<Core>,
    clock: Arc<AtomicI64>,
    host: HostRecord,
    remote: Arc<FakeRemote>,
    target_id: String,
    host_key: String,
    _tmp: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let dirs = crate::paths::DataDirs::create(&data, Some(tmp.path())).unwrap();
        std::fs::write(dirs.proxy.join("ca.crt"), "isolated existing ca").unwrap();
        std::fs::write(dirs.proxy.join("ca.key"), "isolated existing key").unwrap();
        let ports: Vec<u16> = (0..5).map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect::<Vec<_>>().iter().map(|l| l.local_addr().unwrap().port()).collect();
        let core = Core::start(data, tmp.path().join("no-proxy-binary"), Arc::new(Quiet), StartOptions {
            values_root: Some(tmp.path().to_path_buf()),
            resume_key: Some([9; 32]),
            settings: vec![(crate::settings::API_BIND.into(), json!("127.0.0.1")),
                (crate::settings::API_PORT.into(), json!(0)),
                (crate::settings::PROXY_BIND.into(), json!("127.0.0.1")),
                (crate::settings::PROXY_PORT.into(), json!(ports[0])),
                (crate::settings::PROXY_HTTP_PORT.into(), json!(ports[1])),
                (crate::settings::PROXY_HTTPS_PORT.into(), json!(ports[2])),
                (crate::settings::PROXY_MGMT_PORT.into(), json!(ports[3])),
                (crate::settings::PROXY_METRICS_PORT.into(), json!(ports[4]))],
        }).unwrap();
        let clock = Arc::new(AtomicI64::new(now()));
        let time = clock.clone();
        lock(&core.generation).clock = Arc::new(move || time.load(Ordering::SeqCst));
        let remote = Arc::new(FakeRemote::default());
        core.install_ssh_remote(remote.clone());
        let host = HostRecord { id: new_uuid_v4(), info: HostInfo { hostname: "devbox".into(), ..Default::default() },
            name: String::new(), address: "127.0.0.1".into(), paired_at: now(), last_seen: None, revoked_at: None,
            machine_hint: None };
        core.store.insert_host(&host, &asm_proto::crypto::sha256(host.id.as_bytes())).unwrap();
        let mut f = Self { core, clock, host, remote, target_id: String::new(), host_key: host_key(), _tmp: tmp };
        f.target_id = f.add_target("web.example.com", true, &f.host_key.clone());
        f
    }

    fn draft(name: &str, allow_privileged: bool, key: &str) -> ffi::SshTargetDraft {
        ffi::SshTargetDraft {
            id: None, expected_revision: None, name: name.into(), destination: String::new(),
            agent_hostname: String::new(), agent_port: 22, privileged_login: "root".into(), allow_privileged,
            host_keys: vec![key.into()], log_units: vec!["web.service".into()],
            restart_units: vec!["web.service".into()], max_duration_secs: 3600, users: vec![],
        }
    }

    /// An enrolled target.
    fn add_target(&self, name: &str, allow_privileged: bool, key: &str) -> String {
        let target = self.core.save_ssh_target(Self::draft(name, allow_privileged, key)).unwrap();
        assert_eq!(target.state, ffi::SshTargetState::NotEnrolled);
        assert_eq!((target.destination.as_str(), target.agent_hostname.as_str()), (name, name));
        self.core.install_ssh_target_enrollment(&target.id).unwrap();
        target.id
    }

    fn now(&self) -> i64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn advance(&self, secs: i64) -> i64 {
        self.clock.fetch_add(secs, Ordering::SeqCst) + secs
    }

    fn request(&self, targets: &[&str], access: SshAccess, grants: &[&str]) -> Result<RequestState> {
        self.request_as(targets, access, grants, None)
    }

    fn request_as(&self, targets: &[&str], access: SshAccess, grants: &[&str], user: Option<&str>)
        -> Result<RequestState>
    {
        self.core.create_request(&self.host, "127.0.0.1", RequestBody::Ssh {
            targets: targets.iter().map(|t| (*t).into()).collect(), access,
            grants: grants.iter().map(|g| (*g).into()).collect(), user: user.map(Into::into), new_lease: true,
            reason: "find the 502".into(), agent: "claude".into(),
        })
    }

    fn approve(&self, request_id: &str, target_ids: &[&str], access: ffi::SshAccess, grants: &[&str], duration_secs: u64)
        -> Result<()>
    {
        self.approve_as(request_id, target_ids, access, grants, None, duration_secs)
    }

    fn approve_as(&self, request_id: &str, target_ids: &[&str], access: ffi::SshAccess, grants: &[&str],
        user: Option<&str>, duration_secs: u64) -> Result<()>
    {
        self.core.resolve_request(request_id, ffi::Decision::ApproveSsh {
            target_ids: target_ids.iter().map(|t| (*t).into()).collect(), access,
            grants: grants.iter().map(|g| (*g).into()).collect(), user: user.map(Into::into), duration_secs,
        })
    }

    /// Saves the fixture target with these users, then marks it enrolled.
    fn set_users(&self, allow_privileged: bool, users: &[(&str, Option<&str>)]) -> Result<ffi::SshTargetInfo> {
        let revision = self.core.list_ssh_targets().unwrap().into_iter().find(|t| t.id == self.target_id).unwrap().revision;
        let info = self.core.save_ssh_target(ffi::SshTargetDraft {
            id: Some(self.target_id.clone()), expected_revision: Some(revision),
            users: users.iter().map(|(name, admin)| ffi::SshTargetUser {
                name: (*name).into(), admin: admin.map(Into::into),
            }).collect(),
            ..Self::draft("web.example.com", allow_privileged, &self.host_key)
        })?;
        self.core.install_ssh_target_enrollment(&self.target_id).unwrap();
        Ok(info)
    }

    fn result(&self, request_id: &str) -> SshResult {
        let state = self.core.request_state(&self.host.id, request_id).unwrap();
        let Some(RequestResult::Ssh(result)) = state.result else { panic!("no SSH result: {state:?}") };
        result
    }

    /// A privileged lease on the fixture target for 600 s.
    fn lease(&self) -> SshResult {
        let pending = self.request(&["web.example.com"], SshAccess::Privileged, &[]).unwrap();
        self.approve(&pending.request_id, &[&self.target_id], ffi::SshAccess::Privileged, &[], 600).unwrap();
        self.result(&pending.request_id)
    }

    fn extend(&self, lease_id: &str) -> Result<RequestState> {
        self.core.create_request(&self.host, "127.0.0.1", RequestBody::SshExtend {
            lease_id: lease_id.into(), reason: "more time".into(), agent: "claude".into(),
        })
    }

    fn sign(&self, lease_id: &str, data: &[u8]) -> Result<SshSignResponse> {
        self.core.ssh_sign(&self.host, &asm_proto::crypto::sha256(self.host.id.as_bytes()),
            SshSignRequest { lease_id: lease_id.into(), data: b64_encode(data) })
    }

    fn cleanup(&self, lease_id: &str, target_id: &str) -> SshCleanup {
        self.core.store.get_ssh_lease(lease_id).unwrap().unwrap().cleanup[target_id].clone()
    }

    /// The entry once `done` holds for it (fails after 10 s).
    fn wait_cleanup(&self, lease_id: &str, target_id: &str, done: impl Fn(&SshCleanup) -> bool) -> SshCleanup {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let current = self.cleanup(lease_id, target_id);
            if done(&current) {
                return current;
            }
            assert!(Instant::now() < deadline, "cleanup never reached the expected state: {current:?}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_settled(&self, lease_id: &str) -> SshCleanup {
        self.wait_cleanup(lease_id, &self.target_id, |c| c.state != SshCleanupState::Pending || c.attempts > 0)
    }

    fn ui_cleanup(&self, lease_id: &str) -> Option<ffi::SshCleanupState> {
        let lease = self.core.list_leases().into_iter().find(|l| l.lease_id == lease_id).unwrap();
        lease.ssh.unwrap().targets[0].cleanup
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.core.shutdown();
    }
}

/// The certified public key inside an `ssh-ed25519-cert-v01@openssh.com` blob.
fn certified_key(certificate: &str) -> [u8; 32] {
    let blob = certificate_blob(certificate).unwrap();
    let mut r = Reader::new(&blob);
    assert_eq!(r.string().unwrap(), CERT_TYPE.as_bytes());
    r.string().unwrap();
    r.string().unwrap().try_into().unwrap()
}

fn force_command(cert: &Certificate) -> Option<&str> {
    cert.critical_options().get("force-command").map(String::as_str)
}

fn keygen_list(certificate: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lease-cert.pub");
    std::fs::write(&path, format!("{certificate}\n")).unwrap();
    let out = Command::new(SSH_KEYGEN).arg("-L").arg("-f").arg(&path).output().unwrap();
    assert!(out.status.success(), "ssh-keygen -L failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

// ---- requests, approvals and signing ----

#[test]
fn approved_privileged_lease_signs_pinned_logins_until_revoked() {
    let f = Fixture::new();
    let result = f.lease();
    assert_eq!(result.targets[0].login, "asm-priv");
    let lease = f.core.store.get_ssh_lease(&result.lease_id).unwrap().unwrap();
    let text = keygen_list(&result.certificate);
    assert!(text.contains(&format!("asm-{}-privileged", f.target_id)), "{text}");
    assert!(text.contains(&format!("force-command asm-shell lease={} until={}", lease.id, lease.expires_at)), "{text}");
    assert!(text.contains(&format!("Key ID: \"asm-lease-{}\"", lease.id)), "{text}");
    assert!(text.contains("permit-pty"), "{text}");

    // A hostbound login to the pinned host is signed with the certified key.
    let cert = certificate_blob(&result.certificate).unwrap();
    let pinned = host_key_blob(&f.host_key).unwrap();
    let data = hostbound_payload("asm-priv", CERT_TYPE, &cert, &pinned);
    let signed = f.sign(&result.lease_id, &data).unwrap();
    let blob = b64_decode(&signed.signature).unwrap();
    let mut r = Reader::new(&blob);
    assert_eq!(r.string().unwrap(), b"ssh-ed25519");
    let sig: [u8; 64] = r.string().unwrap().try_into().unwrap();
    VerifyingKey::from_bytes(&certified_key(&result.certificate)).unwrap()
        .verify(&data, &Signature::from_bytes(&sig)).unwrap();
    f.sign(&result.lease_id, &payload("asm-priv", "publickey", true, CERT_TYPE, &cert, b"")).unwrap();

    // A host this lease doesn't pin, and the other login, are refused.
    let other_host = host_key_blob(&host_key()).unwrap();
    let unpinned = hostbound_payload("asm-priv", CERT_TYPE, &cert, &other_host);
    assert_eq!(f.sign(&result.lease_id, &unpinned).unwrap_err().message,
        "the request is for a host this lease does not pin");
    let other = payload("asm-ops", "publickey", true, CERT_TYPE, &cert, b"");
    assert_eq!(f.sign(&result.lease_id, &other).unwrap_err().code, ErrorCode::Invalid);

    // An identical request while the lease is active reuses it at once.
    let again = f.core.create_request(&f.host, "127.0.0.1", RequestBody::Ssh {
        targets: vec!["web.example.com".into()], access: SshAccess::Privileged, grants: vec![], user: None,
        new_lease: false, reason: "again".into(), agent: "claude".into(),
    }).unwrap();
    assert_eq!(again.status, RequestStatus::Approved);
    assert_eq!(f.result(&again.request_id).lease_id, result.lease_id);

    f.core.revoke_lease(&result.lease_id).unwrap();
    assert!(f.sign(&result.lease_id, &data).unwrap_err().message.contains("SSH lease has ended"));
}

#[test]
fn signing_is_rate_limited_per_lease() {
    let f = Fixture::new();
    let result = f.lease();
    let cert = certificate_blob(&result.certificate).unwrap();
    let data = payload("asm-priv", "publickey", true, CERT_TYPE, &cert, b"");
    for _ in 0..30 {
        f.sign(&result.lease_id, &data).unwrap();
    }
    assert_eq!(f.sign(&result.lease_id, &data).unwrap_err().code, ErrorCode::RateLimited);
    f.advance(61);
    f.sign(&result.lease_id, &data).unwrap();
}

#[test]
fn signing_rechecks_the_token() {
    let f = Fixture::new();
    let result = f.lease();
    let cert = certificate_blob(&result.certificate).unwrap();
    let data = payload("asm-priv", "publickey", true, CERT_TYPE, &cert, b"");
    let stale = f.core.ssh_sign(&f.host, &[0; 32],
        SshSignRequest { lease_id: result.lease_id.clone(), data: b64_encode(&data) });
    assert_eq!(stale.unwrap_err().code, ErrorCode::Unauthorized);
    f.sign(&result.lease_id, &data).unwrap();
    f.core.revoke_host(&f.host.id).unwrap();
    assert_eq!(f.sign(&result.lease_id, &data).unwrap_err().code, ErrorCode::Unauthorized);
}

#[test]
fn only_the_owner_of_a_lease_uses_its_signing_budget() {
    let f = Fixture::new();
    let result = f.lease();
    let cert = certificate_blob(&result.certificate).unwrap();
    let data = payload("asm-priv", "publickey", true, CERT_TYPE, &cert, b"");
    let other = HostRecord { id: new_uuid_v4(), ..f.host.clone() };
    let other_token = asm_proto::crypto::sha256(other.id.as_bytes());
    f.core.store.insert_host(&other, &other_token).unwrap();
    for _ in 0..40 {
        let error = f.core.ssh_sign(&other, &other_token,
            SshSignRequest { lease_id: result.lease_id.clone(), data: b64_encode(&data) }).unwrap_err();
        assert_eq!(error.code, ErrorCode::NotFound);
        assert_eq!(f.sign("no-such-lease", &data).unwrap_err().code, ErrorCode::NotFound);
    }
    for _ in 0..30 {
        f.sign(&result.lease_id, &data).unwrap();
    }
    assert_eq!(f.sign(&result.lease_id, &data).unwrap_err().code, ErrorCode::RateLimited);
}

#[test]
fn signing_stops_when_a_lease_target_changes_or_goes() {
    let f = Fixture::new();
    let result = f.lease();
    let cert = certificate_blob(&result.certificate).unwrap();
    let data = payload("asm-priv", "publickey", true, CERT_TYPE, &cert, b"");
    f.sign(&result.lease_id, &data).unwrap();
    // A change that did not end the lease still stops it signing.
    let target = f.core.store.get_ssh_target(&f.target_id).unwrap().unwrap();
    f.core.store.update_ssh_target(&f.target_id, &target.name, &target.config, target.revision).unwrap();
    assert!(f.core.store.get_ssh_lease(&result.lease_id).unwrap().unwrap().is_active(f.now()));
    assert_eq!(f.sign(&result.lease_id, &data).unwrap_err().message, "the SSH target changed; request a new lease");

    f.core.install_ssh_target_enrollment(&f.target_id).unwrap();
    let result = f.lease();
    let cert = certificate_blob(&result.certificate).unwrap();
    let data = payload("asm-priv", "publickey", true, CERT_TYPE, &cert, b"");
    f.sign(&result.lease_id, &data).unwrap();
    assert!(f.core.store.delete_ssh_target(&f.target_id).unwrap());
    assert_eq!(f.sign(&result.lease_id, &data).unwrap_err().message, "the SSH target changed; request a new lease");
}

#[test]
fn approvals_stay_within_the_requested_grants_and_the_targets() {
    let f = Fixture::new();
    let pending = f.request(&["web.example.com"], SshAccess::Restricted, &["logs:web.service"]).unwrap();
    let decide = |access, grants: &[&str], duration| f.approve(&pending.request_id, &[&f.target_id], access, grants, duration);
    assert_eq!(decide(ffi::SshAccess::Restricted, &["logs:web.service", "restart:web.service"], 600)
        .unwrap_err().message, "approve only grants the request asked for");
    assert!(decide(ffi::SshAccess::Restricted, &["logs"], 600).is_err());
    assert!(decide(ffi::SshAccess::Restricted, &["logs:web.service"], 7200).unwrap_err().message.contains("duration"));
    decide(ffi::SshAccess::Restricted, &["logs:web.service"], 600).unwrap();
    let result = f.result(&pending.request_id);
    let lease = f.core.store.get_ssh_lease(&result.lease_id).unwrap().unwrap();
    assert_eq!(lease.grant.targets[0].login, "asm-ops");
    assert_eq!(lease.grant.grants, ["logs:web.service"]);
    let cert = Certificate::from_openssh(&lease.certificate).unwrap();
    assert_eq!(cert.valid_principals(), [format!("asm-{}-restricted", f.target_id)]);
    assert_eq!(force_command(&cert),
        Some(format!("asm-grant lease={} until={} logs:web.service", lease.id, lease.expires_at).as_str()));
    assert!(cert.extensions().is_empty());

    // A privileged request narrowed to restricted may choose any grant the target allows.
    let pending = f.request(&["web.example.com"], SshAccess::Privileged, &[]).unwrap();
    f.approve(&pending.request_id, &[&f.target_id], ffi::SshAccess::Restricted, &["restart:web.service"], 600).unwrap();
    assert_eq!(f.result(&pending.request_id).grants, ["restart:web.service"]);

    // The operator may widen a restricted request to privileged access.
    let pending = f.request(&["web.example.com"], SshAccess::Restricted, &["logs:web.service"]).unwrap();
    f.approve(&pending.request_id, &[&f.target_id], ffi::SshAccess::Privileged, &[], 600).unwrap();
    let result = f.result(&pending.request_id);
    assert_eq!((result.access, result.targets[0].login.as_str()), (SshAccess::Privileged, "asm-priv"));
}

#[test]
fn privileged_access_needs_a_target_that_allows_it() {
    let f = Fixture::new();
    let db = f.add_target("db.example.com", false, &host_key());
    assert_eq!(f.request(&["db.example.com"], SshAccess::Privileged, &[]).unwrap_err().message,
        "SSH target db.example.com does not allow privileged access");
    let pending = f.request(&["db.example.com"], SshAccess::Restricted, &["logs:web.service"]).unwrap();
    assert_eq!(f.approve(&pending.request_id, &[&db], ffi::SshAccess::Privileged, &[], 600).unwrap_err().message,
        "SSH target db.example.com does not allow privileged access");
    assert_eq!(f.request(&["db.example.com"], SshAccess::Restricted, &["logs:other.service"]).unwrap_err().message,
        "SSH target db.example.com does not allow logs:other.service");
}

#[test]
fn access_as_a_user_runs_as_a_user_every_target_allows() {
    let f = Fixture::new();
    let info = f.set_users(true, &[("ops", Some("in group sudo")), ("deploy", None)]).unwrap();
    let names: Vec<_> = info.users.iter().map(|u| u.name.as_str()).collect();
    assert_eq!(names, ["deploy", "ops"]);
    assert_eq!(f.core.ssh_target_summaries().unwrap()[0].users, ["deploy", "ops"]);
    assert!(f.core.ssh_enroll_script(&f.target_id).unwrap().contains("USERS='deploy:0\nops:1'"));

    let pending = f.request_as(&["web.example.com"], SshAccess::User, &[], Some("deploy")).unwrap();
    f.approve_as(&pending.request_id, &[&f.target_id], ffi::SshAccess::User, &[], Some("deploy"), 600).unwrap();
    let result = f.result(&pending.request_id);
    assert_eq!((result.access, result.user.as_deref(), result.targets[0].login.as_str()),
        (SshAccess::User, Some("deploy"), "asm-priv"));
    let lease = f.core.store.get_ssh_lease(&result.lease_id).unwrap().unwrap();
    let cert = Certificate::from_openssh(&lease.certificate).unwrap();
    assert_eq!(cert.valid_principals(), [format!("asm-{}-user", f.target_id)]);
    assert_eq!(force_command(&cert),
        Some(format!("asm-shell lease={} until={} as=deploy", lease.id, lease.expires_at).as_str()));
    assert!(cert.extensions().contains_key("permit-pty"));

    // Users the target doesn't allow are refused, at the request and at approval.
    assert_eq!(f.request_as(&["web.example.com"], SshAccess::User, &[], Some("www-data")).unwrap_err().message,
        "SSH target web.example.com does not allow access as www-data; see asm ssh hosts");
    let pending = f.request_as(&["web.example.com"], SshAccess::User, &[], Some("deploy")).unwrap();
    let decide = |access, user| f.approve_as(&pending.request_id, &[&f.target_id], access, &[], user, 600);
    assert_eq!(decide(ffi::SshAccess::User, Some("thinkscape")).unwrap_err().message,
        "SSH target web.example.com does not allow access as thinkscape; see asm ssh hosts");
    assert!(decide(ffi::SshAccess::Privileged, Some("deploy")).is_err());
    // The operator may choose another user.
    decide(ffi::SshAccess::User, Some("ops")).unwrap();
    assert_eq!(f.result(&pending.request_id).user.as_deref(), Some("ops"));

    // A user that can become root needs privileged access allowed on its target.
    assert_eq!(f.set_users(false, &[("ops", Some("in group sudo"))]).unwrap_err().message,
        "ops can become root (in group sudo): allow privileged access to let agents use it");
    assert_eq!(f.set_users(true, &[("root", None)]).unwrap_err().message,
        "root is the privileged login; agents get it with privileged access");
    // A target that allows only users still refuses privileged access.
    f.set_users(false, &[("deploy", None)]).unwrap();
    assert_eq!(f.request(&["web.example.com"], SshAccess::Privileged, &[]).unwrap_err().message,
        "SSH target web.example.com does not allow privileged access");
}

#[test]
fn enrollment_checks_a_login_as_each_user() {
    let f = Fixture::new();
    let revision = f.set_users(false, &[("deploy", None)]).unwrap().revision;
    f.remote.answer(out(0, "asm-enroll-ok\n", ""));
    f.remote.answer(out(0, "asm-end-ok 0\n", ""));
    f.remote.answer(out(126, "", "asm: sudo: a password is required\n"));
    let error = f.core.enroll_ssh_target(&f.target_id, revision).unwrap_err();
    assert_eq!(error.message,
        "enrolled, but a test login as asm-priv as deploy failed: host reported an unexpected result: asm: sudo: a password is required");
    let calls = f.remote.calls();
    assert_eq!(calls.len(), 3, "no privileged check without privileged access: {calls:?}");
    let RemoteAuth::Certificate { login, command, .. } = &calls[2].auth else { panic!("{calls:?}") };
    assert_eq!((*login, *command), ("asm-priv", Some("true")));
    let cert = Certificate::from_openssh(calls[2].cert.as_deref().unwrap()).unwrap();
    assert!(force_command(&cert).unwrap().ends_with(" as=deploy"), "{:?}", force_command(&cert));
    assert_eq!(cert.valid_principals(), [format!("asm-{}-user", f.target_id)]);
}

#[test]
fn unknown_or_unenrolled_targets_are_refused() {
    let f = Fixture::new();
    assert_eq!(f.request(&["db"], SshAccess::Privileged, &[]).unwrap_err().message,
        "no SSH host named db; see asm ssh hosts");
    let target = f.core.store.get_ssh_target(&f.target_id).unwrap().unwrap();
    let mut changed = target.config.clone();
    changed.log_units.clear();
    f.core.store.update_ssh_target(&f.target_id, "web.example.com", &changed, target.revision).unwrap();
    assert!(f.request(&["web.example.com"], SshAccess::Privileged, &[]).unwrap_err().message.contains("is not enrolled"));
    assert_eq!(f.core.list_ssh_targets().unwrap()[0].state, ffi::SshTargetState::NeedsReenroll);
}

#[test]
fn targets_need_their_own_host_keys_and_keep_destination_while_enrolled() {
    let f = Fixture::new();
    let message = f.core.save_ssh_target(Fixture::draft("db", true, &f.host_key)).unwrap_err().message;
    assert_eq!(message, format!("host key {} is already pinned for SSH target web.example.com; each target needs \
        its own host keys", host_key_fingerprint(&f.host_key)));
    let current = f.core.list_ssh_targets().unwrap().remove(0);
    let edit = |name: &str, key: &str| ffi::SshTargetDraft {
        id: Some(f.target_id.clone()), expected_revision: Some(current.revision), ..Fixture::draft(name, true, key)
    };
    let refused = "remove asm from the host before changing its destination or host keys";
    assert_eq!(f.core.save_ssh_target(edit("web2.example.com", &f.host_key)).unwrap_err().message, refused);
    assert_eq!(f.core.save_ssh_target(edit("web.example.com", &host_key())).unwrap_err().message, refused);
    let saved = f.core.save_ssh_target(ffi::SshTargetDraft { allow_privileged: false, ..edit("web.example.com", &f.host_key) })
        .unwrap();
    assert_eq!((saved.allow_privileged, saved.state), (false, ffi::SshTargetState::NeedsReenroll));
    let summaries = f.core.ssh_target_summaries().unwrap();
    assert!(summaries.is_empty());
    f.core.install_ssh_target_enrollment(&f.target_id).unwrap();
    let summary = f.core.ssh_target_summaries().unwrap().remove(0);
    assert_eq!((summary.privileged_login, summary.grants),
        (None, vec!["logs:web.service".to_string(), "restart:web.service".to_string()]));
}

// ---- extensions ----

#[test]
fn approved_extension_replaces_the_certificate() {
    let f = Fixture::new();
    let result = f.lease();
    let before = f.core.store.get_ssh_lease(&result.lease_id).unwrap().unwrap();
    let old_cert = certificate_blob(&result.certificate).unwrap();
    let first = f.extend(&result.lease_id).unwrap();
    assert_eq!(first.status, RequestStatus::Pending);
    let second = f.extend(&result.lease_id).unwrap();
    assert_eq!(second.request_id, first.request_id);
    let detail = f.core.snapshot().pending.into_iter().find(|p| p.id == first.request_id).unwrap().detail;
    let ffi::RequestDetail::SshExtend { lease_id, issue, targets, max_duration_secs, .. } = detail else {
        panic!("not an extension: {detail:?}")
    };
    assert_eq!((lease_id.as_str(), issue, targets.len(), max_duration_secs), (result.lease_id.as_str(), None, 1, 3600));

    f.advance(100);
    f.core.resolve_request(&first.request_id, ffi::Decision::ApproveSshExtend { duration_secs: 1200 }).unwrap();
    let extended = f.result(&first.request_id);
    assert_eq!(extended.lease_id, result.lease_id);
    let lease = f.core.store.get_ssh_lease(&result.lease_id).unwrap().unwrap();
    assert_eq!(lease.expires_at, f.now() + 1200);
    assert!(lease.expires_at > before.expires_at);
    let old = Certificate::from_openssh(&before.certificate).unwrap();
    let new = Certificate::from_openssh(&extended.certificate).unwrap();
    assert_eq!((new.valid_principals(), new.key_id()), (old.valid_principals(), old.key_id()));
    assert_eq!(new.public_key(), old.public_key());
    assert_eq!(force_command(&new), Some(format!("asm-shell lease={} until={}", lease.id, lease.expires_at).as_str()));

    let new_cert = certificate_blob(&extended.certificate).unwrap();
    assert!(f.sign(&lease.id, &payload("asm-priv", "publickey", true, CERT_TYPE, &old_cert, b"")).is_err());
    f.sign(&lease.id, &payload("asm-priv", "publickey", true, CERT_TYPE, &new_cert, b"")).unwrap();
}

#[test]
fn extension_must_move_the_end_later() {
    let f = Fixture::new();
    let result = f.lease();
    let pending = f.extend(&result.lease_id).unwrap();
    let error = f.core.resolve_request(&pending.request_id, ffi::Decision::ApproveSshExtend { duration_secs: 300 })
        .unwrap_err();
    assert_eq!(error.message, "the lease already ends later; choose a longer duration");
    assert_eq!(f.core.request_state(&f.host.id, &pending.request_id).unwrap().status, RequestStatus::Pending);
    assert!(f.core.resolve_request(&pending.request_id, ffi::Decision::ApproveSshExtend { duration_secs: 7200 })
        .unwrap_err().message.contains("choose a duration between 1 minute and 60 minutes"));
}

#[test]
fn extension_of_an_ended_lease_is_denied() {
    let f = Fixture::new();
    let result = f.lease();
    let pending = f.extend(&result.lease_id).unwrap();
    f.core.revoke_lease(&result.lease_id).unwrap();
    let detail = f.core.snapshot().pending.into_iter().find(|p| p.id == pending.request_id).unwrap().detail;
    assert!(matches!(&detail, ffi::RequestDetail::SshExtend { issue: Some(i), .. } if i == "the lease has ended"));
    let error = f.core.resolve_request(&pending.request_id, ffi::Decision::ApproveSshExtend { duration_secs: 1200 })
        .unwrap_err();
    assert_eq!(error.message, "the SSH lease ended before the extension was approved");
    assert_eq!(f.core.request_state(&f.host.id, &pending.request_id).unwrap().status, RequestStatus::Denied);
    assert!(f.extend(&result.lease_id).unwrap_err().message.starts_with("no active SSH lease"));
}

#[test]
fn extension_after_a_target_change_is_denied() {
    let f = Fixture::new();
    let result = f.lease();
    let pending = f.extend(&result.lease_id).unwrap();
    let target = f.core.store.get_ssh_target(&f.target_id).unwrap().unwrap();
    f.core.store.update_ssh_target(&f.target_id, &target.name, &target.config, target.revision).unwrap();
    let error = f.core.resolve_request(&pending.request_id, ffi::Decision::ApproveSshExtend { duration_secs: 1200 })
        .unwrap_err();
    assert_eq!(error.message, "SSH target web.example.com changed; request a new lease");
    assert_eq!(f.core.request_state(&f.host.id, &pending.request_id).unwrap().status, RequestStatus::Denied);
}

// ---- session cleanup ----

#[test]
fn revoked_lease_is_cleaned_up_with_a_short_cleanup_certificate() {
    let f = Fixture::new();
    let result = f.lease();
    let lease = f.core.store.get_ssh_lease(&result.lease_id).unwrap().unwrap();
    f.remote.answer(out(0, &format!("ending 3 asm-priv {}\nasm-end-ok 1\n", lease.id), ""));
    f.core.revoke_lease(&lease.id).unwrap();
    let done = f.wait_settled(&lease.id);
    assert_eq!((done.state, done.detail.as_str()), (SshCleanupState::Done, "host reported: ended 1 sessions"));
    assert_eq!(f.ui_cleanup(&lease.id), Some(ffi::SshCleanupState::Done));

    let calls = f.remote.calls();
    assert_eq!(calls.len(), 1);
    let RemoteAuth::Certificate { login, dir, command } = &calls[0].auth else { panic!("{calls:?}") };
    assert_eq!((*login, *command), ("asm-ops", None));
    assert!(!dir.exists(), "the run directory is removed");
    assert!(dir.starts_with(&f.core.dirs.ssh_run));
    assert_eq!(calls[0].stdin, format!("end {} {}\n", lease.id, lease.expires_at));
    let cert = Certificate::from_openssh(calls[0].cert.as_deref().unwrap()).unwrap();
    assert_eq!(cert.valid_principals(), [format!("asm-{}-cleanup", f.target_id)]);
    assert!(cert.key_id().starts_with("asm-cleanup-"), "{}", cert.key_id());
    assert_eq!(cert.valid_before() - cert.valid_after(), 360);
    assert!(cert.critical_options().is_empty() && cert.extensions().is_empty());
}

#[test]
fn unreachable_hosts_are_retried_with_backoff() {
    let f = Fixture::new();
    let result = f.lease();
    f.remote.answer(out(255, "", "ssh: connect to host web.example.com port 22: Connection refused\n"));
    f.core.revoke_lease(&result.lease_id).unwrap();
    let ended_at = f.now();
    let retrying = f.wait_settled(&result.lease_id);
    assert_eq!((retrying.state, retrying.attempts, retrying.due), (SshCleanupState::Pending, 1, ended_at + 60));
    assert_eq!(retrying.detail, "could not reach the host: ssh: connect to host web.example.com port 22: Connection refused");
    assert_eq!(f.ui_cleanup(&result.lease_id), Some(ffi::SshCleanupState::Retrying));
    assert_eq!(f.core.next_ssh_wake(f.now()), Some(ended_at + 60));

    f.remote.answer(out(0, "asm-end-ok 0\n", ""));
    let later = f.advance(61);
    f.core.sweep_ssh_at(later);
    let done = f.wait_cleanup(&result.lease_id, &f.target_id, |c| c.state == SshCleanupState::Done);
    assert_eq!(done.detail, "host reported: ended 0 sessions");
    assert_eq!(f.remote.calls().len(), 2);
}

#[test]
fn a_busy_host_is_retried() {
    let f = Fixture::new();
    let result = f.lease();
    f.remote.answer(out(3, "asm-end-error busy another asm operation is running on this host\n", ""));
    f.core.revoke_lease(&result.lease_id).unwrap();
    let retrying = f.wait_settled(&result.lease_id);
    assert_eq!((retrying.state, retrying.attempts), (SshCleanupState::Pending, 1));
    assert_eq!(retrying.detail, "host reported: another asm operation is running on this host (busy)");
}

#[test]
fn cleanup_gives_up_after_24_hours() {
    let f = Fixture::new();
    let result = f.lease();
    f.remote.answer(out(255, "", "timeout\n"));
    f.remote.answer(out(255, "", "timeout\n"));
    f.core.revoke_lease(&result.lease_id).unwrap();
    f.wait_settled(&result.lease_id);
    let later = f.advance(86_401);
    f.core.sweep_ssh_at(later);
    let failed = f.wait_cleanup(&result.lease_id, &f.target_id, |c| c.state != SshCleanupState::Pending);
    assert_eq!(failed.state, SshCleanupState::Failed);
    assert!(failed.detail.starts_with("could not reach the host for 24 hours"), "{}", failed.detail);
    assert_eq!(f.ui_cleanup(&result.lease_id), Some(ffi::SshCleanupState::Failed));
    f.core.retry_ssh_cleanup(&result.lease_id).unwrap();
    let done = f.wait_cleanup(&result.lease_id, &f.target_id, |c| c.state == SshCleanupState::Done);
    assert_eq!(done.attempts, 0);
}

#[test]
fn host_errors_and_malformed_results_fail() {
    let f = Fixture::new();
    let cases = [
        ("asm-end-error sessions could not end 1 of 1 sessions\n", "host reported: could not end 1 of 1 sessions (sessions)"),
        ("asm-end-ok 1 2\n", "host reported an unexpected result"),
        ("asm-end-ok x\n", "host reported an unexpected result"),
    ];
    for (answer, expected) in cases {
        let result = f.lease();
        f.remote.answer(out(0, answer, ""));
        f.core.revoke_lease(&result.lease_id).unwrap();
        let failed = f.wait_settled(&result.lease_id);
        assert_eq!(failed.state, SshCleanupState::Failed, "{answer}");
        assert!(failed.detail.starts_with(expected), "{answer}: {}", failed.detail);
    }
}

#[test]
fn hostile_host_text_is_sanitized() {
    let f = Fixture::new();
    let result = f.lease();
    let message = format!("evil\u{202E}txt\x1b[31m{}", "x".repeat(500));
    f.remote.answer(out(3, &format!("asm-end-error sessions {message}\n"), ""));
    f.core.revoke_lease(&result.lease_id).unwrap();
    let failed = f.wait_settled(&result.lease_id);
    let shown = failed.detail.strip_prefix("host reported: ").unwrap().strip_suffix(" (sessions)").unwrap();
    assert!(!failed.detail.chars().any(|c| c.is_control() || is_bidi_control(c)), "{}", failed.detail);
    assert!(shown.starts_with("evil?txt?[31m"), "{shown}");
    assert_eq!(shown.chars().count(), 201);
    assert!(shown.ends_with('…'));
}

#[test]
fn a_slow_target_does_not_delay_another() {
    let f = Fixture::new();
    let db = f.add_target("db.example.com", true, &host_key());
    let pending = f.request(&["web.example.com", "db.example.com"], SshAccess::Privileged, &[]).unwrap();
    f.approve(&pending.request_id, &[&f.target_id, &db], ffi::SshAccess::Privileged, &[], 600).unwrap();
    let result = f.result(&pending.request_id);
    let (release, blocked) = mpsc::channel::<()>();
    let blocked = Mutex::new(blocked);
    let slow = f.target_id.clone();
    *lock(&f.remote.handler) = Some(Arc::new(move |call: &Call| {
        if call.target_id == slow {
            lock(&blocked).recv().unwrap();
        }
        out(0, "asm-end-ok 1\n", "")
    }));
    f.core.revoke_lease(&result.lease_id).unwrap();
    let fast = f.wait_cleanup(&result.lease_id, &db, |c| c.state == SshCleanupState::Done);
    assert_eq!(fast.detail, "host reported: ended 1 sessions");
    assert_eq!(f.cleanup(&result.lease_id, &f.target_id).state, SshCleanupState::Pending);
    release.send(()).unwrap();
    f.wait_cleanup(&result.lease_id, &f.target_id, |c| c.state == SshCleanupState::Done);
}

// ---- enrollment and removal ----

#[test]
fn removal_ends_pending_cleanup() {
    let f = Fixture::new();
    let result = f.lease();
    f.remote.answer(out(0, "asm-unenroll-ok 2\n", ""));
    f.core.unenroll_ssh_target(&f.target_id).unwrap();
    let done = f.cleanup(&result.lease_id, &f.target_id);
    assert_eq!((done.state, done.detail.as_str()), (SshCleanupState::Done, "host reported: asm removed; ended 2 sessions"));
    let calls = f.remote.calls();
    assert_eq!(calls.len(), 1);
    assert!(matches!(calls[0].auth, RemoteAuth::Operator { .. }), "{calls:?}");
    assert!(calls[0].stdin.starts_with(&format!("set -- '{}'\n", f.target_id)));
    assert_eq!(f.core.list_ssh_targets().unwrap()[0].state, ffi::SshTargetState::NotEnrolled);
    assert!(f.core.store.get_ssh_lease(&result.lease_id).unwrap().unwrap().revoked_at.is_some());
}

#[test]
fn enrollment_finishes_with_test_logins() {
    let f = Fixture::new();
    let revision = f.core.list_ssh_targets().unwrap()[0].revision;
    f.remote.answer(out(0, "installing\nasm-enroll-ok\n", ""));
    f.remote.answer(out(0, "asm-end-ok 0\n", ""));
    f.remote.answer(out(0, "", ""));
    let info = f.core.enroll_ssh_target(&f.target_id, revision).unwrap();
    assert_eq!(info.state, ffi::SshTargetState::Enrolled);
    let calls = f.remote.calls();
    assert_eq!(calls.len(), 3);
    assert!(matches!(calls[0].auth, RemoteAuth::Operator { .. }), "{calls:?}");
    assert!(calls[0].stdin.contains(&format!("TID='{}'", f.target_id)));
    let RemoteAuth::Certificate { login, command, .. } = &calls[1].auth else { panic!("{calls:?}") };
    assert_eq!((*login, *command, calls[1].stdin.as_str()), ("asm-ops", None, "check\n"));
    let RemoteAuth::Certificate { login, command, .. } = &calls[2].auth else { panic!("{calls:?}") };
    assert_eq!((*login, *command), ("asm-priv", Some("true")));
    let cert = Certificate::from_openssh(calls[2].cert.as_deref().unwrap()).unwrap();
    assert!(force_command(&cert).unwrap().starts_with("asm-shell lease="));
    assert_eq!(cert.valid_principals(), [format!("asm-{}-privileged", f.target_id)]);
    assert!(cert.key_id().starts_with("asm-check-"));

    f.remote.answer(out(0, "asm-enroll-ok\n", ""));
    f.remote.answer(out(0, "asm-end-ok 0\n", ""));
    f.remote.answer(out(255, "", "asm-priv@web.example.com: Permission denied (publickey).\n"));
    let error = f.core.enroll_ssh_target(&f.target_id, revision).unwrap_err();
    assert!(error.message.starts_with("enrolled, but a test login as asm-priv failed"), "{}", error.message);
    let target = f.core.list_ssh_targets().unwrap().remove(0);
    assert_eq!(target.state, ffi::SshTargetState::Failed);
    assert!(target.error.unwrap().contains("Permission denied"));
}

#[test]
fn enrollment_reports_host_errors() {
    let f = Fixture::new();
    let revision = f.core.list_ssh_targets().unwrap()[0].revision;
    f.remote.answer(out(3, "asm-enroll-error user-exists user asm-ops exists and was not created by asm here\n", ""));
    let error = f.core.enroll_ssh_target(&f.target_id, revision).unwrap_err();
    assert_eq!(error.message, "host reported: user asm-ops exists and was not created by asm here (user-exists)");
    assert_eq!(f.remote.calls().len(), 1);
}

#[test]
fn enrollment_refuses_an_unusable_route_before_changing_the_host() {
    let f = Fixture::new();
    let lease = f.lease();
    let revision = f.core.list_ssh_targets().unwrap()[0].revision;
    let message = "asm cannot use the ProxyCommand of web.example.com for unattended runs: it uses %n, %r, %k or %C";
    *lock(&f.remote.route) = Some(RemoteError::Local(message.into()));
    assert_eq!(f.core.enroll_ssh_target(&f.target_id, revision).unwrap_err().message, message);
    assert!(f.remote.calls().is_empty());
    assert_eq!(f.core.list_ssh_targets().unwrap()[0].state, ffi::SshTargetState::Enrolled);
    assert!(f.core.store.get_ssh_lease(&lease.lease_id).unwrap().unwrap().is_active(f.now()));
}

#[test]
fn enrolling_again_ends_the_targets_leases() {
    let f = Fixture::new();
    let result = f.lease();
    let cert = certificate_blob(&result.certificate).unwrap();
    let data = payload("asm-priv", "publickey", true, CERT_TYPE, &cert, b"");
    let revision = f.core.list_ssh_targets().unwrap()[0].revision;
    f.remote.answer(out(3, "asm-enroll-error sshd sshd refused the configuration\n", ""));
    f.core.enroll_ssh_target(&f.target_id, revision).unwrap_err();
    assert_eq!(f.core.list_ssh_targets().unwrap()[0].state, ffi::SshTargetState::Failed);
    assert!(f.core.store.get_ssh_lease(&result.lease_id).unwrap().unwrap().revoked_at.is_some());
    assert!(f.sign(&result.lease_id, &data).unwrap_err().message.contains("SSH lease has ended"));
    let done = f.wait_settled(&result.lease_id);
    assert_eq!((done.state, done.detail.as_str()), (SshCleanupState::Done, "host reported: ended 0 sessions"));
}

#[test]
fn removing_a_failed_target_ends_its_leases() {
    let f = Fixture::new();
    let result = f.lease();
    let cert = certificate_blob(&result.certificate).unwrap();
    let data = payload("asm-priv", "publickey", true, CERT_TYPE, &cert, b"");
    // As after an interrupted removal: the target failed with the lease still active.
    assert!(f.core.store.set_ssh_enrollment(&f.target_id, &[SshEnrollState::Enrolled], SshEnrollState::Failed,
        None, None, Some("interrupted; run it again"), f.now()).unwrap());
    f.sign(&result.lease_id, &data).unwrap();
    f.core.remove_ssh_target(&f.target_id).unwrap();
    assert!(f.core.list_ssh_targets().unwrap().is_empty());
    assert!(f.core.store.get_ssh_lease(&result.lease_id).unwrap().unwrap().revoked_at.is_some());
    assert!(f.sign(&result.lease_id, &data).unwrap_err().message.contains("SSH lease has ended"));
    let failed = f.wait_settled(&result.lease_id);
    assert_eq!((failed.state, failed.detail.as_str()), (SshCleanupState::Failed, "the target was removed from asm"));
    assert!(f.remote.calls().is_empty());
}

// ---- pure helpers ----

#[test]
fn operator_options_pin_the_host_and_quote_the_path() {
    let options = ssh_options(Path::new("/Users/x/Library/Application Support/asm/ssh/known_hosts"), "0123abcd").unwrap();
    assert_eq!(options[0], "-T");
    for wanted in ["UserKnownHostsFile=\"/Users/x/Library/Application Support/asm/ssh/known_hosts\"",
        "HostKeyAlias=asm-target-0123abcd", "StrictHostKeyChecking=yes", "GlobalKnownHostsFile=/dev/null",
        "KnownHostsCommand=none", "ClearAllForwardings=yes", "RequestTTY=no", "LogLevel=ERROR"]
    {
        let at = options.iter().position(|o| o == wanted).unwrap_or_else(|| panic!("{wanted}: {options:?}"));
        assert_eq!(options[at - 1], "-o");
    }
    assert_eq!(options.len(), 1 + 2 * 23);
    assert_eq!(ssh_options(Path::new("/a\"b/known_hosts"), "0123abcd").unwrap_err().message,
        "the data directory path cannot contain \" or %");
    assert!(ssh_options(Path::new("/a%h/known_hosts"), "0123abcd").is_err());
}

#[test]
fn certificate_configs_use_only_the_certificate() {
    let known_hosts = Path::new("/data dir/ssh/known_hosts");
    let run_dir = Path::new("/run/asm/ssh/1");
    let route = parse_route("user x\nhostname web.example.com\nport 2222\nproxycommand none\nproxyjump none\n").unwrap();
    assert_eq!(route, Route { hostname: "web.example.com".into(), port: 2222, proxy_command: None, proxy_jump: None });
    let config = certificate_config(&route, known_hosts, "0123abcd", "asm-ops", run_dir, None).unwrap();
    assert!(config.starts_with("Host asm-target\n  HostName web.example.com\n  Port 2222\n  User asm-ops\n  \
        HostKeyAlias asm-target-0123abcd\n  UserKnownHostsFile \"/data dir/ssh/known_hosts\"\n"), "{config}");
    assert!(config.contains("  IdentityAgent none\n"));
    assert_eq!(config.matches("IdentityFile").count(), 1);
    assert!(config.contains("  IdentityFile \"/run/asm/ssh/1/id\"\n"));
    assert_eq!(config.matches("CertificateFile").count(), 1);
    assert!(config.contains("  CertificateFile \"/run/asm/ssh/1/id-cert.pub\"\n"));
    for absent in ["Include", "ProxyJump", "ProxyCommand"] {
        assert!(!config.contains(absent), "{absent}: {config}");
    }

    let proxy = |route: &str| {
        let route = parse_route(&format!("hostname web\nport 22\n{route}\n")).unwrap();
        certificate_config(&route, known_hosts, "0123abcd", "asm-ops", run_dir, None)
            .map(|c| c.lines().find(|l| l.contains("ProxyCommand")).unwrap_or_default().to_owned())
    };
    assert_eq!(proxy("proxyjump bastion").unwrap(),
        "  ProxyCommand /usr/bin/ssh -o BatchMode=yes -W '[%h]:%p' 'ssh://bastion'");
    assert_eq!(proxy("proxyjump a,deploy@b:2222").unwrap(),
        "  ProxyCommand /usr/bin/ssh -o BatchMode=yes -J 'a' -W '[%h]:%p' 'ssh://deploy@b:2222'");
    assert_eq!(proxy("proxycommand nc %h %p").unwrap(), "  ProxyCommand nc %h %p");
    for refused in ["proxyjump a b", "proxyjump fe80::1"] {
        assert_eq!(proxy(refused).unwrap_err().message,
            "asm cannot use the ProxyJump/ProxyCommand of web for unattended cleanup", "{refused}");
    }
    let tokens = "asm cannot use the ProxyCommand of web for unattended runs: it uses %n, %r, %k or %C";
    for refused in ["proxycommand nc %r %h", "proxycommand nc %n", "proxycommand x %k", "proxycommand x %C", "proxycommand x %%%r"] {
        assert_eq!(proxy(refused).unwrap_err().message, tokens, "{refused}");
    }
    assert_eq!(proxy("proxycommand nc %%r %h %p").unwrap(), "  ProxyCommand nc %%r %h %p");

    let route = parse_route("hostname web\nport 22\nproxyjump bastion\n").unwrap();
    let config = certificate_config(&route, known_hosts, "0123abcd", "asm-priv", run_dir,
        Some(Path::new("/tmp/ssh config"))).unwrap();
    assert!(config.contains("  User asm-priv\n"));
    assert!(config.contains("  ProxyCommand /usr/bin/ssh -o BatchMode=yes -F \"/tmp/ssh config\" -W '[%h]:%p' 'ssh://bastion'\n"));
    assert!(parse_route("port 22\n").is_err());
}

#[test]
fn host_results_are_strict() {
    let f = Fixture::new();
    let target = f.core.store.get_ssh_target(&f.target_id).unwrap().unwrap();
    let run = |status, stdout: &str, counts| host_result(&target, RemoteOutput {
        status, stdout: stdout.into(), stderr: "ssh: oops\n".into(),
    }, "asm-end-ok", "asm-end-error", counts);
    assert_eq!(run(0, "noise\nasm-end-ok 3\n", 1), Ok(vec![3]));
    assert_eq!(run(0, "asm-end-ok\n", 0), Ok(vec![]));
    assert_eq!(run(255, "asm-end-ok 3\n", 1), Err(RemoteError::Unreachable("ssh: oops".into())));
    assert_eq!(run(1, "asm-end-ok 3\n", 1).unwrap_err().to_string(), "host reported an unexpected result: asm-end-ok 3");
    assert_eq!(run(0, "asm-end-ok 3 \n", 1), Ok(vec![3]), "lines are trimmed");
    assert!(run(0, "asm-end-ok  3\n", 1).is_err());
    assert_eq!(run(3, "asm-end-error Bad code\n", 1).unwrap_err(),
        RemoteError::Host { code: "unexpected".into(), message: "asm-end-error Bad code".into() });
    assert_eq!(run(3, "", 1).unwrap_err().to_string(), "host reported an unexpected result: ssh: oops");
}

#[test]
fn host_user_lists_are_parsed_strictly() {
    let users = parse_host_users("motd line\nasm-user www-data 33 1 0 -\nasm-user deploy 1001 0 1 -\n\
        asm-user ops 1002 0 1 in group sudo\nasm-users-ok\n").unwrap();
    assert_eq!(users[0], ffi::SshHostUser {
        name: "deploy".into(), uid: 1001, system: false, login_shell: true, admin: None,
    });
    assert_eq!((users[1].name.as_str(), users[1].admin.as_deref()), ("ops", Some("in group sudo")));
    assert_eq!((users[2].name.as_str(), users[2].system, users[2].login_shell), ("www-data", true, false));
    for bad in [
        "asm-user deploy 1001 0 1 -\n",
        "asm-user Deploy 1001 0 1 -\nasm-users-ok\n",
        "asm-user deploy x 0 1 -\nasm-users-ok\n",
        "asm-user deploy 1001 2 1 -\nasm-users-ok\n",
        "asm-user deploy 1001 0 1\nasm-users-ok\n",
    ] {
        assert!(parse_host_users(bad).is_err(), "{bad}");
    }
}

#[test]
fn host_check_failures_are_told_apart() {
    let alias = "asm-target-0123abcd";
    let check = |status, stderr: &str| check_outcome(status, stderr, "web", "deploy", alias);
    assert_eq!(check(0, "").unwrap(), CheckOutcome::Ran);
    // ssh names the target by its HostKeyAlias, and a jump host by its own name.
    let changed = "Host key for asm-target-0123abcd has changed and you have requested strict checking.\nHost key verification failed.\n";
    assert_eq!(check(255, changed).unwrap(), CheckOutcome::KeyMismatch);
    let jump = "No ED25519 host key is known for bastion and you have requested strict checking.\nHost key verification failed.\n";
    let err = check(255, jump).unwrap_err().message;
    assert_eq!(err, "could not reach web: a jump host failed its host key check: No ED25519 host key is known for bastion \
        and you have requested strict checking. Connect to it once with ssh in Terminal and check its fingerprint, then try again");
    assert_eq!(check(255, "deploy@web: Permission denied (publickey).\n").unwrap_err().message,
        "asm could not log in to web as deploy with your ssh setup: deploy@web: Permission denied (publickey).");
    assert_eq!(check(1, "sudo: a password is required\n").unwrap_err().message,
        "deploy on web needs passwordless sudo: sudo: a password is required");
    assert_eq!(check(255, "ssh: connect to host web port 22: Connection refused\n").unwrap(),
        CheckOutcome::Unreachable("could not reach web: ssh: connect to host web port 22: Connection refused".into()));
    assert_eq!(check(2, "").unwrap_err().message, "checking web failed: exit status 2");

    // Runs on an existing target classify the same messages under its own alias.
    let f = Fixture::new();
    let target = f.core.store.get_ssh_target(&f.target_id).unwrap().unwrap();
    let changed = changed.replace("0123abcd", &target.id);
    assert_eq!(connection_error(&target, &changed), RemoteError::HostKeyChanged);
    assert!(matches!(connection_error(&target, jump), RemoteError::Unreachable(m) if m.contains("jump host")));
    assert!(matches!(connection_error(&target, "ssh: connect to host web port 22: Connection refused\n"),
        RemoteError::Unreachable(m) if m == "ssh: connect to host web port 22: Connection refused"));
}

#[test]
fn a_changed_host_key_is_flagged_until_new_keys_are_pinned() {
    let f = Fixture::new();
    let revision = f.core.list_ssh_targets().unwrap()[0].revision;
    f.remote.answer(out(255, "", &format!(
        "Host key for asm-target-{} has changed and you have requested strict checking.\nHost key verification failed.\n",
        f.target_id)));
    let error = f.core.enroll_ssh_target(&f.target_id, revision).unwrap_err();
    assert_eq!(error.message, "the host didn't prove its pinned host key");
    assert!(f.core.list_ssh_targets().unwrap()[0].host_key_changed);

    // Each target needs its own keys, even when replacing them.
    let other_key = host_key();
    f.add_target("db.example.com", false, &other_key);
    assert!(f.core.replace_ssh_host_keys(&f.target_id, revision, vec![other_key]).unwrap_err().message
        .contains("already pinned for SSH target db.example.com"));

    // Pinning reviewed keys clears the mark.
    let new_key = host_key();
    let info = f.core.replace_ssh_host_keys(&f.target_id, revision, vec![new_key.clone()]).unwrap();
    assert!(!info.host_key_changed);
    assert_eq!(info.revision, revision + 1);
    assert_eq!(info.host_keys.iter().map(|k| k.line.as_str()).collect::<Vec<_>>(), [new_key.as_str()]);
}

#[test]
fn replacing_host_keys_ends_the_targets_leases() {
    let f = Fixture::new();
    let lease = f.lease();
    let revision = f.core.list_ssh_targets().unwrap()[0].revision;
    f.core.replace_ssh_host_keys(&f.target_id, revision, vec![host_key()]).unwrap();
    assert!(f.core.store.get_ssh_lease(&lease.lease_id).unwrap().unwrap().revoked_at.is_some());
}
