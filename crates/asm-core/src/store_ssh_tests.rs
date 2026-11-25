use super::*;
use asm_proto::ssh::SshAccess;
use std::collections::BTreeMap;

const HOST_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHNvbWUtMzItYnl0ZS1lZDI1NTE5LWtleS0xMjM0NTY3";
const LEASE_ID: &str = "00000000-0000-4000-8000-000000000001";

fn config() -> SshTargetConfig {
    SshTargetConfig {
        destination: "root@web.example".into(),
        agent_hostname: "web.example".into(),
        agent_port: 22,
        privileged_login: "root".into(),
        allow_privileged: true,
        host_keys: vec![HOST_KEY.into()],
        log_units: vec!["web.service".into()],
        restart_units: vec!["web.service".into()],
        max_duration_secs: 3600,
        users: vec![SshTargetUser { name: "deploy".into(), admin: None }],
    }
}

fn target() -> SshTargetRecord {
    SshTargetRecord {
        id: "0a1b2c3d".into(), name: "web".into(), config: config(), revision: 1,
        enroll_state: SshEnrollState::NotEnrolled, enrolled_revision: 0, enrolled_ca: None,
        enroll_at: None, enroll_error: None, created_at: 100,
    }
}

fn lease() -> SshLeaseRecord {
    SshLeaseRecord {
        id: LEASE_ID.into(), host_id: "host".into(), agent: "claude".into(),
        reason: "check".into(),
        grant: SshGrant {
            access: SshAccess::Restricted,
            targets: vec![SshGrantTarget {
                target_id: "0a1b2c3d".into(), name: "web".into(), revision: 1, login: "asm-ops".into(),
                hostname: "web.example".into(), port: 22, host_keys: vec![HOST_KEY.into()],
            }],
            grants: vec!["logs:web.service".into()],
            user: None,
        },
        certificate: "ssh-ed25519-cert-v01@openssh.com AAAA asm-lease-x".into(),
        created_at: 100, expires_at: 200, revoked_at: None, ended_at: None, cleanup: BTreeMap::new(),
    }
}

fn history(id: &str) -> HistoryRecord {
    HistoryRecord {
        id: id.into(), kind: "ssh".into(), host_id: Some("host".into()), host_label: "devbox".into(),
        summary: "ssh web".into(), status: "approved".into(), deny_reason: None, created_at: 90, resolved_at: 100,
    }
}

fn pending(at: i64) -> SshCleanup {
    SshCleanup { state: SshCleanupState::Pending, at, detail: String::new(), attempts: 0, due: 0 }
}

#[test]
fn ssh_tables_appear_in_an_existing_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.db");
    let head_schema = SCHEMA.split("CREATE TABLE IF NOT EXISTS ssh_targets").next().unwrap();
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(head_schema).unwrap();
        assert!(!conn.prepare("SELECT 1 FROM sqlite_master WHERE name = 'ssh_targets'").unwrap().exists([]).unwrap());
    }
    let store = Store::open(&path).unwrap();
    let db = store.db();
    for table in ["ssh_targets", "ssh_leases"] {
        assert!(db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1").unwrap()
            .exists([table]).unwrap(), "{table}");
    }
}

#[test]
fn targets_round_trip_with_revision_and_enrollment_checks() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("asm.db")).unwrap();
    store.insert_ssh_target(&target()).unwrap();
    let duplicate = SshTargetRecord { id: "11111111".into(), ..target() };
    assert!(store.insert_ssh_target(&duplicate).unwrap_err().message.contains("already exists"));
    assert_eq!(store.get_ssh_target("0a1b2c3d").unwrap().unwrap(), target());
    assert_eq!(store.ssh_target_by_name("web").unwrap().unwrap().id, "0a1b2c3d");

    let mut changed = config();
    changed.allow_privileged = false;
    assert_eq!(store.update_ssh_target("0a1b2c3d", "web2", &changed, 1).unwrap(), 2);
    assert!(store.update_ssh_target("0a1b2c3d", "web2", &changed, 1).unwrap_err().message.contains("changed"));
    let stored = store.get_ssh_target("0a1b2c3d").unwrap().unwrap();
    assert_eq!((stored.name.as_str(), stored.revision, stored.config.allow_privileged), ("web2", 2, false));

    assert!(!store.set_ssh_enrollment("0a1b2c3d", &[SshEnrollState::Enrolled], SshEnrollState::Enrolling,
        None, None, None, 5).unwrap());
    assert!(store.set_ssh_enrollment("0a1b2c3d", &[SshEnrollState::NotEnrolled, SshEnrollState::Failed],
        SshEnrollState::Enrolling, None, None, None, 5).unwrap());
    assert!(store.set_ssh_enrollment("0a1b2c3d", &[SshEnrollState::Enrolling], SshEnrollState::Enrolled,
        Some(2), Some("SHA256:ca"), None, 6).unwrap());
    let stored = store.get_ssh_target("0a1b2c3d").unwrap().unwrap();
    assert_eq!((stored.enroll_state, stored.enrolled_revision, stored.enrolled_ca.as_deref(), stored.enroll_at),
        (SshEnrollState::Enrolled, 2, Some("SHA256:ca"), Some(6)));
    assert!(store.delete_ssh_target("0a1b2c3d").unwrap());
    assert!(store.list_ssh_targets().unwrap().is_empty());
}

#[test]
fn target_settings_are_canonical_and_validated() {
    let mut bad = config();
    bad.host_keys = vec!["ssh-ed25519 AAAAB3NzaC1yc2E=".into()];
    assert!(bad.validate().is_err());
    let mut commented = config();
    commented.host_keys = vec![format!("{HOST_KEY} host")];
    assert!(commented.validate().is_err());
    commented.canonicalize();
    commented.validate().unwrap();

    let mut unsorted = config();
    unsorted.restart_units = vec!["b.service".into(), "a.service".into(), "a.service".into()];
    unsorted.log_units = vec!["z.service".into(), "y.service".into()];
    assert_eq!(unsorted.validate().unwrap_err().message, "log units must be sorted and unique");
    unsorted.canonicalize();
    assert_eq!(unsorted.restart_units, ["a.service", "b.service"]);
    assert_eq!(unsorted.log_units, ["y.service", "z.service"]);
    unsorted.validate().unwrap();
    let mut many = config();
    many.log_units = (0..33).map(|i| format!("u{i:02}.service")).collect();
    assert_eq!(many.validate().unwrap_err().message, "at most 32 log units");

    for destination in ["web.example.com", "root@10.0.0.5", "[fe80::1]", "deploy@web-1_a"] {
        validate_destination(destination).unwrap();
    }
    for destination in ["", "-oProxyCommand=x", "web example", "web\"x", "a%h", "web;rm", &"a".repeat(256)] {
        assert!(validate_destination(destination).unwrap_err().message.starts_with("enter an SSH destination"),
            "{destination}");
    }
}

#[test]
fn leases_round_trip_end_once_and_report_pending_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("asm.db")).unwrap();
    let lease = lease();
    store.insert_ssh_lease_with_request(&lease, &[], &history("req")).unwrap();
    assert_eq!(store.get_ssh_lease(&lease.id).unwrap().unwrap(), lease);
    assert_eq!(store.active_ssh_leases(150).unwrap().len(), 1);
    assert!(store.active_ssh_leases(200).unwrap().is_empty());
    assert!(store.ssh_leases_expiring(199).unwrap().is_empty());
    assert_eq!(store.ssh_leases_expiring(200).unwrap().len(), 1);
    assert_eq!(store.ssh_leases_of_host("host").unwrap().len(), 1);
    assert!(store.ssh_leases_needing_cleanup().unwrap().is_empty());

    let cleanup = BTreeMap::from([("0a1b2c3d".to_string(), pending(150))]);
    assert!(store.end_ssh_lease(&lease.id, Some(150), 150, &cleanup).unwrap());
    assert!(!store.end_ssh_lease(&lease.id, None, 160, &BTreeMap::new()).unwrap());
    assert!(store.ssh_leases_expiring(300).unwrap().is_empty());
    let ended = store.get_ssh_lease(&lease.id).unwrap().unwrap();
    assert_eq!((ended.revoked_at, ended.ended_at, ended.status(150)), (Some(150), Some(150), LeaseStatus::Revoked));
    assert_eq!(store.ssh_leases_needing_cleanup().unwrap().len(), 1);
    let retrying = BTreeMap::from([("0a1b2c3d".to_string(), SshCleanup {
        state: SshCleanupState::Pending, at: 160, detail: "could not reach the host: x".into(), attempts: 2, due: 280,
    })]);
    store.set_ssh_cleanup(&lease.id, &retrying).unwrap();
    assert_eq!(store.ssh_leases_needing_cleanup().unwrap()[0].cleanup, retrying);
    let done = BTreeMap::from([("0a1b2c3d".to_string(), SshCleanup {
        state: SshCleanupState::Done, at: 300, detail: "host reported: ended 0 sessions".into(), attempts: 2, due: 0,
    })]);
    store.set_ssh_cleanup(&lease.id, &done).unwrap();
    assert!(store.ssh_leases_needing_cleanup().unwrap().is_empty());
    assert_eq!(store.get_ssh_lease(&lease.id).unwrap().unwrap().cleanup, done);
}

#[test]
fn cleanup_entries_without_retry_fields_load() {
    let entry: SshCleanup = serde_json::from_str(r#"{"state":"pending","at":5,"detail":""}"#).unwrap();
    assert_eq!((entry.attempts, entry.due), (0, 0));
    assert!(serde_json::from_str::<SshCleanup>(r#"{"state":"first_pass_done","at":5,"detail":""}"#).is_err());
}

#[test]
fn extension_replaces_the_certificate_of_an_active_lease_only() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("asm.db")).unwrap();
    let lease = lease();
    store.insert_ssh_lease_with_request(&lease, &[], &history("req")).unwrap();
    let stale = store.extend_ssh_lease_with_request(&lease.id, 150, 400, "cert-2", &[], &history("ext-0"));
    assert_eq!(stale.unwrap_err().message, "the SSH lease has ended; request a new lease with asm ssh request");
    store.extend_ssh_lease_with_request(&lease.id, 200, 400, "cert-2", &[], &history("ext-1")).unwrap();
    let extended = store.get_ssh_lease(&lease.id).unwrap().unwrap();
    assert_eq!((extended.expires_at, extended.certificate.as_str()), (400, "cert-2"));

    let cleanup = BTreeMap::from([("0a1b2c3d".to_string(), pending(300))]);
    assert!(store.end_ssh_lease(&lease.id, Some(300), 300, &cleanup).unwrap());
    assert!(store.extend_ssh_lease_with_request(&lease.id, 400, 500, "cert-3", &[], &history("ext-2")).is_err());
    assert_eq!(store.get_ssh_lease(&lease.id).unwrap().unwrap().expires_at, 400);
}

#[test]
fn persisted_leases_need_uuid_and_target_ids() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("asm.db")).unwrap();
    let bad_id = SshLeaseRecord { id: "lease-1".into(), ..lease() };
    store.insert_ssh_lease_with_request(&bad_id, &[], &history("req-1")).unwrap();
    assert_eq!(store.get_ssh_lease("lease-1").unwrap_err().message, "invalid persisted SSH lease");
    let mut bad_target = SshLeaseRecord { id: "00000000-0000-4000-8000-000000000002".into(), ..lease() };
    bad_target.grant.targets[0].target_id = "../etc".into();
    store.insert_ssh_lease_with_request(&bad_target, &[], &history("req-2")).unwrap();
    assert!(store.get_ssh_lease(&bad_target.id).is_err());
}
