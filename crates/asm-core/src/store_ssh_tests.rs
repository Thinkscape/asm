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
        reload_units: vec!["nginx.service".into()],
        read_files: vec!["/etc/nginx/nginx.conf".into()],
        max_duration_secs: 3600,
        users: vec![SshTargetUser { name: "deploy".into(), admin: None }],
    }
}

fn target() -> SshTargetRecord {
    SshTargetRecord {
        id: "0a1b2c3d".into(), name: "web".into(), config: config(), revision: 1,
        enroll_state: SshEnrollState::NotEnrolled, enrolled_revision: 0, enrolled_ca: None,
        enroll_at: None, enroll_error: None, created_at: 100, enrolled_scripts: None,
    }
}

fn lease() -> SshLeaseRecord {
    SshLeaseRecord {
        id: LEASE_ID.into(), host_id: "host".into(), agent: "claude".into(),
        reason: "check".into(),
        grant: SshGrant {
            requested: SshRequested {
                access: SshAccess::Restricted, grants: vec!["logs:web.service".into()], user: None,
                target_ids: vec!["0a1b2c3d".into()],
            },
            targets: vec![SshGrantTarget {
                target_id: "0a1b2c3d".into(), name: "web".into(), revision: 1, login: "asm-ops".into(),
                hostname: "web.example".into(), port: 22, host_keys: vec![HOST_KEY.into()],
                access: SshAccess::Restricted, grants: vec!["logs:web.service".into()], user: None,
            }],
        },
        certificates: BTreeMap::from([("0a1b2c3d".into(), "ssh-ed25519-cert-v01@openssh.com AAAA asm-lease-x".into())]),
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
    SshCleanup::new(SshCleanupState::Pending, at, String::new(), 0, 0)
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

/// The tables as 0.9.0 created them.
const SSH_TABLES_0_9: &str = "
CREATE TABLE ssh_targets(
    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, config TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    enroll_state TEXT NOT NULL DEFAULT 'not_enrolled'
        CHECK (enroll_state IN ('not_enrolled','enrolling','enrolled','failed','removing')),
    enrolled_revision INTEGER NOT NULL DEFAULT 0, enrolled_ca TEXT, enroll_at INTEGER, enroll_error TEXT,
    created_at INTEGER NOT NULL);
CREATE TABLE ssh_leases(
    id TEXT PRIMARY KEY, host_id TEXT NOT NULL, agent TEXT NOT NULL, reason TEXT NOT NULL,
    grant_json TEXT NOT NULL, certificate TEXT NOT NULL, created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL, revoked_at INTEGER, ended_at INTEGER, cleanup TEXT NOT NULL DEFAULT '{}');
CREATE INDEX ssh_leases_host ON ssh_leases(host_id);
";

#[test]
fn leases_and_targets_of_0_9_migrate_to_per_target_access() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.db");
    let head_schema = SCHEMA.split("CREATE TABLE IF NOT EXISTS ssh_targets").next().unwrap();
    let old_config = serde_json::json!({
        "destination": "root@web.example", "agent_hostname": "web.example", "agent_port": 22,
        "privileged_login": "root", "allow_privileged": true, "host_keys": [HOST_KEY],
        "log_units": ["web.service"], "restart_units": [], "max_duration_secs": 3600,
        "users": [{ "name": "deploy" }],
    });
    let target = |id: &str, name: &str| serde_json::json!({
        "target_id": id, "name": name, "revision": 2, "login": "asm-priv", "hostname": name, "port": 22,
        "host_keys": [HOST_KEY],
    });
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(head_schema).unwrap();
        conn.execute_batch(SSH_TABLES_0_9).unwrap();
        conn.execute("INSERT INTO ssh_targets(id, name, config, revision, enroll_state, enrolled_revision, enrolled_ca,
            created_at) VALUES('0a1b2c3d', 'web', ?1, 2, 'enrolled', 2, 'SHA256:ca', 50)", [old_config.to_string()]).unwrap();
        let grants = [
            (LEASE_ID, serde_json::json!({ "access": "user", "grants": [], "user": "deploy",
                "targets": [target("0b000000", "web2"), target("0a1b2c3d", "web")] }), "cert-1"),
            ("00000000-0000-4000-8000-000000000002", serde_json::json!({ "access": "restricted",
                "grants": ["logs:web.service"], "targets": [target("0a1b2c3d", "web")] }), "cert-2"),
        ];
        for (id, grant, certificate) in grants {
            conn.execute("INSERT INTO ssh_leases(id, host_id, agent, reason, grant_json, certificate, created_at,
                expires_at, ended_at, cleanup) VALUES(?1, 'host', 'claude', 'check', ?2, ?3, 100, 200, 200,
                '{\"0a1b2c3d\":{\"state\":\"done\",\"at\":210,\"detail\":\"host reported: ended 0 sessions\"}}')",
                params![id, grant.to_string(), certificate]).unwrap();
        }
    }
    for _ in 0..2 {
        let store = Store::open(&path).unwrap();
        let web = store.get_ssh_target("0a1b2c3d").unwrap().unwrap();
        assert_eq!((web.enroll_state, web.enrolled_scripts, web.config.reload_units.len(), web.config.read_files.len()),
            (SshEnrollState::Enrolled, None, 0, 0));

        let user = store.get_ssh_lease(LEASE_ID).unwrap().unwrap();
        assert_eq!(user.grant.requested, SshRequested {
            access: SshAccess::User, grants: vec![], user: Some("deploy".into()),
            target_ids: vec!["0a1b2c3d".into(), "0b000000".into()],
        });
        let access: Vec<_> = user.grant.targets.iter()
            .map(|t| (t.target_id.as_str(), t.login.as_str(), t.access, t.user.as_deref())).collect();
        assert_eq!(access, [("0b000000", "asm-priv", SshAccess::User, Some("deploy")),
            ("0a1b2c3d", "asm-priv", SshAccess::User, Some("deploy"))]);
        assert_eq!(user.certificates, BTreeMap::from([("0a1b2c3d".into(), "cert-1".into()), ("0b000000".into(), "cert-1".into())]));
        let cleanup = &user.cleanup["0a1b2c3d"];
        assert_eq!((cleanup.state, cleanup.changes.len(), cleanup.changes_total), (SshCleanupState::Done, 0, 0));

        let restricted = store.get_ssh_lease("00000000-0000-4000-8000-000000000002").unwrap().unwrap();
        assert_eq!((restricted.grant.requested.access, restricted.grant.requested.grants.as_slice()),
            (SshAccess::Restricted, ["logs:web.service".to_string()].as_slice()));
        assert_eq!(restricted.grant.targets[0].grants, ["logs:web.service"]);
        assert_eq!(restricted.certificates["0a1b2c3d"], "cert-2");

        let db = store.db();
        let column = |table: &str, name: &str| db.prepare("SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2").unwrap()
            .exists([table, name]).unwrap();
        assert!(!column("ssh_leases", "certificate") && column("ssh_leases", "certificates"));
        assert!(column("ssh_targets", "enrolled_scripts"));
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
        None, None, None, None, 5).unwrap());
    assert!(store.set_ssh_enrollment("0a1b2c3d", &[SshEnrollState::NotEnrolled, SshEnrollState::Failed],
        SshEnrollState::Enrolling, None, None, None, None, 5).unwrap());
    assert!(store.set_ssh_enrollment("0a1b2c3d", &[SshEnrollState::Enrolling], SshEnrollState::Enrolled,
        Some(2), Some("SHA256:ca"), Some("0123456789abcdef"), None, 6).unwrap());
    let stored = store.get_ssh_target("0a1b2c3d").unwrap().unwrap();
    assert_eq!((stored.enroll_state, stored.enrolled_revision, stored.enrolled_ca.as_deref(), stored.enroll_at,
        stored.enrolled_scripts.as_deref()), (SshEnrollState::Enrolled, 2, Some("SHA256:ca"), Some(6), Some("0123456789abcdef")));
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
    unsorted.reload_units = vec!["r.service".into(), "q.service".into(), "r.service".into()];
    unsorted.read_files = vec!["/srv/b".into(), "/etc/a".into(), "/srv/b".into()];
    assert_eq!(unsorted.validate().unwrap_err().message, "log units must be sorted and unique");
    unsorted.canonicalize();
    assert_eq!(unsorted.restart_units, ["a.service", "b.service"]);
    assert_eq!(unsorted.log_units, ["y.service", "z.service"]);
    assert_eq!(unsorted.reload_units, ["q.service", "r.service"]);
    assert_eq!(unsorted.read_files, ["/etc/a", "/srv/b"]);
    unsorted.validate().unwrap();
    let mut many = config();
    many.log_units = (0..33).map(|i| format!("u{i:02}.service")).collect();
    assert_eq!(many.validate().unwrap_err().message, "at most 32 log units");
    let mut many = config();
    many.reload_units = (0..33).map(|i| format!("u{i:02}.service")).collect();
    assert_eq!(many.validate().unwrap_err().message, "at most 32 reload units");
    let mut many = config();
    many.read_files = (0..33).map(|i| format!("/etc/f{i:02}")).collect();
    assert_eq!(many.validate().unwrap_err().message, "at most 32 files");
    let mut bad = config();
    bad.reload_units = vec!["nginx".into()];
    assert!(bad.validate().is_err());
    let mut bad = config();
    bad.read_files = vec!["/etc/../shadow".into()];
    assert!(bad.validate().unwrap_err().message.starts_with("invalid file"));
    // Settings saved before reload units and files existed still load.
    let mut old = serde_json::to_value(config()).unwrap();
    old.as_object_mut().unwrap().retain(|k, _| k != "reload_units" && k != "read_files");
    let old: SshTargetConfig = serde_json::from_value(old).unwrap();
    assert!(old.reload_units.is_empty() && old.read_files.is_empty());

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
    let retrying = BTreeMap::from([("0a1b2c3d".to_string(),
        SshCleanup::new(SshCleanupState::Pending, 160, "could not reach the host: x".into(), 2, 280))]);
    store.set_ssh_cleanup(&lease.id, &retrying).unwrap();
    assert_eq!(store.ssh_leases_needing_cleanup().unwrap()[0].cleanup, retrying);
    let done = BTreeMap::from([("0a1b2c3d".to_string(), SshCleanup {
        changes: vec!["/etc/cron.d/x".into()], changes_total: 3,
        ..SshCleanup::new(SshCleanupState::Done, 300, "host reported: ended 0 sessions".into(), 2, 0)
    })]);
    store.set_ssh_cleanup(&lease.id, &done).unwrap();
    assert!(store.ssh_leases_needing_cleanup().unwrap().is_empty());
    assert_eq!(store.get_ssh_lease(&lease.id).unwrap().unwrap().cleanup, done);
}

#[test]
fn cleanup_entries_without_retry_fields_load() {
    let entry: SshCleanup = serde_json::from_str(r#"{"state":"pending","at":5,"detail":""}"#).unwrap();
    assert_eq!((entry.attempts, entry.due, entry.changes.len(), entry.changes_total), (0, 0, 0, 0));
    assert!(serde_json::from_str::<SshCleanup>(r#"{"state":"first_pass_done","at":5,"detail":""}"#).is_err());
}

#[test]
fn extension_replaces_the_certificates_of_an_active_lease_only() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("asm.db")).unwrap();
    let lease = lease();
    store.insert_ssh_lease_with_request(&lease, &[], &history("req")).unwrap();
    let certificates = |c: &str| BTreeMap::from([("0a1b2c3d".to_string(), c.to_string())]);
    let stale = store.extend_ssh_lease_with_request(&lease.id, 150, 400, &certificates("cert-2"), &[], &history("ext-0"));
    assert_eq!(stale.unwrap_err().message, "the SSH lease has ended; request a new lease with asm ssh request");
    store.extend_ssh_lease_with_request(&lease.id, 200, 400, &certificates("cert-2"), &[], &history("ext-1")).unwrap();
    let extended = store.get_ssh_lease(&lease.id).unwrap().unwrap();
    assert_eq!((extended.expires_at, extended.certificates), (400, certificates("cert-2")));

    let cleanup = BTreeMap::from([("0a1b2c3d".to_string(), pending(300))]);
    assert!(store.end_ssh_lease(&lease.id, Some(300), 300, &cleanup).unwrap());
    assert!(store.extend_ssh_lease_with_request(&lease.id, 400, 500, &certificates("cert-3"), &[], &history("ext-2")).is_err());
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
    let mut stray = SshLeaseRecord { id: "00000000-0000-4000-8000-000000000003".into(), ..lease() };
    stray.certificates.insert("11111111".into(), "cert".into());
    store.insert_ssh_lease_with_request(&stray, &[], &history("req-3")).unwrap();
    assert_eq!(store.get_ssh_lease(&stray.id).unwrap_err().message, "invalid persisted SSH lease");
}
