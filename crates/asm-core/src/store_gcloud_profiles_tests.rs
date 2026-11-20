use super::*;
use asm_proto::generators::GcloudPermission::{ComputeRead, StorageRead};

const EMAIL: &str = "admin@example.test";
const ACCOUNT: &str = "asm-account-one";
const ID: &str = "112233";

fn key() -> GcloudProfileKey {
    GcloudProfileKey {
        generator_id: "connection-id".into(),
        account_subject: "verified-subject".into(),
        access: GcloudAccessRequest { project_id: "test-project".into(), permissions: vec![StorageRead] },
    }
}

#[test]
fn profile_persists_and_requires_exact_generator_subject_project_and_claims() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("profile.db");
    let key = key();
    {
        let store = Store::open(&path).unwrap();
        store.begin_gcloud_profile(&key, ACCOUNT, EMAIL, None).unwrap();
        assert!(store.mark_gcloud_profile_project_bound(&key, ACCOUNT, ID).is_err());
        store.record_gcloud_profile_identity(&key, ACCOUNT, ID).unwrap();
        assert!(store.mark_gcloud_profile_project_bound(&key, ACCOUNT, "445566").is_err());
        store.mark_gcloud_profile_project_bound(&key, ACCOUNT, ID).unwrap();
        assert!(store.mark_gcloud_profile_ready(&key, ACCOUNT, ID).is_err());
        store.mark_gcloud_profile_token_creator_bound(&key, ACCOUNT, ID).unwrap();
        store.mark_gcloud_profile_ready(&key, ACCOUNT, ID).unwrap();
    }
    let store = Store::open(&path).unwrap();
    assert_eq!(store.gcloud_profile(&key).unwrap().unwrap(), GcloudProfileRecord {
        account_id: ACCOUNT.into(), admin_email: EMAIL.into(), unique_id: Some(ID.into()), phase: GcloudProfilePhase::Ready,
    });
    for different in [
        GcloudProfileKey { generator_id: "other-generator".into(), ..key.clone() },
        GcloudProfileKey { account_subject: "another-subject".into(), ..key.clone() },
        GcloudProfileKey { access: GcloudAccessRequest { project_id: "other-project".into(), ..key.access.clone() }, ..key.clone() },
        GcloudProfileKey { access: GcloudAccessRequest { permissions: vec![StorageRead, ComputeRead], ..key.access.clone() }, ..key.clone() },
    ] {
        assert_eq!(store.gcloud_profile(&different).unwrap(), None);
    }
    store.delete_generator(&key.generator_id).unwrap();
    assert_eq!(store.gcloud_profile_cleanup_resources(&key.generator_id, &key.account_subject, EMAIL).unwrap(),
        vec![(key.access, ACCOUNT.into(), Some(ID.into()))]);
}

#[test]
fn ambiguous_creation_never_adopts_a_name_and_known_identity_is_immutable() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("profile.db")).unwrap();
    let key = key();
    let next = "asm-account-two";
    store.begin_gcloud_profile(&key, ACCOUNT, EMAIL, None).unwrap();
    assert!(store.begin_gcloud_profile(&key, ACCOUNT, EMAIL, Some(ACCOUNT)).is_err());
    assert_eq!(store.gcloud_profile(&key).unwrap().unwrap().account_id, ACCOUNT);
    store.begin_gcloud_profile(&key, next, EMAIL, Some(ACCOUNT)).unwrap();
    assert!(store.record_gcloud_profile_identity(&key, ACCOUNT, ID).is_err());
    store.record_gcloud_profile_identity(&key, next, ID).unwrap();
    assert!(store.record_gcloud_profile_identity(&key, next, "445566").is_err());
    assert!(store.begin_gcloud_profile(&key, "asm-account-three", EMAIL, Some(next)).is_err());
    assert_eq!(store.gcloud_profile_cleanup_resources(&key.generator_id, &key.account_subject, EMAIL).unwrap(), vec![
        (key.access.clone(), ACCOUNT.into(), None), (key.access.clone(), next.into(), Some(ID.into())),
    ]);
    let other = GcloudProfileKey { access: GcloudAccessRequest { permissions: vec![ComputeRead], ..key.access.clone() }, ..key };
    assert!(store.begin_gcloud_profile(&other, ACCOUNT, EMAIL, None).is_err());
    store.begin_gcloud_profile(&other, "asm-account-three", EMAIL, None).unwrap();
    assert!(store.record_gcloud_profile_identity(&other, "asm-account-three", ID).is_err());
}

#[test]
fn managed_lease_storage_keeps_issued_authority_separate_from_the_original_request() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("profile.db")).unwrap();
    let access = key().access;
    let expected = GenerationRequest::GcloudAccess(access.clone());
    let mut lease = LeaseRecord {
        id: "test-lease".into(), host_id: "host-id".into(), vault_id: "generator-id".into(), vault_name: "cloud".into(),
        secret_key: "token".into(), name: asm_proto::generators::GCLOUD_TOKEN_NAME.into(), mode: LeaseMode::Raw,
        fields: Vec::new(), hosts: Vec::new(), reason: "read test storage".into(), agent: "test".into(),
        created_at: 1, expires_at: Some(3), revoked_at: None, source_kind: SourceKind::Generator,
        generation: Some(GenerationGrant::GcloudAccess(GcloudAccessGrant::Requested { access: access.clone() })),
        generator_revision: Some(1), credential_expires_at: Some(2), approval_order: Some(1),
        credential_version: 1, requested_generation: Some(expected.clone()),
    };
    assert!(store.insert_lease(&lease).is_err());
    let grant = GenerationGrant::GcloudAccess(GcloudAccessGrant::Issued {
        service_account_unique_id: ID.into(), service_account_email: gcloud_profile_email(&access.project_id, ACCOUNT), access,
    });
    lease.generation = Some(grant.clone());
    lease.requested_generation = None;
    assert!(store.insert_lease(&lease).is_err());
    lease.requested_generation = Some(GenerationRequest::GcloudAccess(GcloudAccessRequest {
        project_id: "test-project".into(), permissions: vec![StorageRead, ComputeRead],
    }));
    store.insert_lease(&lease).unwrap();
    let persisted = store.get_lease(&lease.id).unwrap().unwrap();
    assert_eq!((persisted.generation, persisted.requested_generation), (Some(grant.clone()), lease.requested_generation.clone()));
    lease.id = "different-project".into();
    lease.requested_generation = Some(GenerationRequest::GcloudAccess(GcloudAccessRequest {
        project_id: "other-project".into(), permissions: vec![StorageRead],
    }));
    store.insert_lease(&lease).unwrap();
    let persisted = store.get_lease(&lease.id).unwrap().unwrap();
    assert_eq!((persisted.generation, persisted.requested_generation), (Some(grant), lease.requested_generation));
    // Simulate malformed persisted state as well as a bad input to insertion.
    store.db().execute("UPDATE leases SET requested_generation = NULL WHERE id = 'test-lease'", []).unwrap();
    assert!(store.get_lease("test-lease").is_err());
}

fn saved_connection(key: &GcloudProfileKey) -> GeneratorRecord {
    GeneratorRecord {
        id: key.generator_id.clone(),
        name: "Google connection".into(),
        revision: 1,
        position: 0,
        require_exact_scope_match: false,
        config: GeneratorConfig::GcloudConnection(crate::generator::GcloudConnectionConfig {
            sdk_path: "/opt/homebrew/bin/gcloud".into(),
            account_subject: key.account_subject.clone(),
            account_email: EMAIL.into(),
        }),
    }
}

fn ready_account(store: &Store, key: &GcloudProfileKey) -> GcloudManagedAccount {
    store.upsert_generator(&saved_connection(key)).unwrap();
    store.begin_gcloud_profile(key, ACCOUNT, EMAIL, None).unwrap();
    store.record_gcloud_profile_identity(key, ACCOUNT, ID).unwrap();
    store.mark_gcloud_profile_project_bound(key, ACCOUNT, ID).unwrap();
    store.mark_gcloud_profile_token_creator_bound(key, ACCOUNT, ID).unwrap();
    store.mark_gcloud_profile_ready(key, ACCOUNT, ID).unwrap();
    store.list_gcloud_managed_accounts().unwrap().pop().unwrap()
}

fn issued_lease(id: &str, key: &GcloudProfileKey, uid: &str) -> LeaseRecord {
    LeaseRecord {
        id: id.into(),
        host_id: "test-host".into(),
        vault_id: key.generator_id.clone(),
        vault_name: "Google connection".into(),
        secret_key: "token".into(),
        name: asm_proto::generators::GCLOUD_TOKEN_NAME.into(),
        mode: LeaseMode::Raw,
        fields: Vec::new(),
        hosts: Vec::new(),
        reason: "inspect test storage".into(),
        agent: "test".into(),
        created_at: 1,
        expires_at: Some(10),
        revoked_at: None,
        source_kind: SourceKind::Generator,
        generation: Some(GenerationGrant::GcloudAccess(GcloudAccessGrant::Issued {
            access: key.access.clone(),
            service_account_unique_id: uid.into(),
            service_account_email: gcloud_profile_email(&key.access.project_id, ACCOUNT),
        })),
        generator_revision: Some(1),
        credential_expires_at: Some(4),
        approval_order: Some(1),
        credential_version: 1,
        requested_generation: Some(GenerationRequest::GcloudAccess(key.access.clone())),
    }
}

#[test]
fn recorded_accounts_include_unverified_attempts_and_deleted_accounts_without_connections() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("profile.db")).unwrap();
    let key = key();
    assert!(!store.has_recorded_gcloud_accounts().unwrap());

    store.begin_gcloud_profile(&key, ACCOUNT, EMAIL, None).unwrap();
    assert!(store.has_recorded_gcloud_accounts().unwrap());

    store.upsert_generator(&saved_connection(&key)).unwrap();
    store.record_gcloud_profile_identity(&key, ACCOUNT, ID).unwrap();
    let account = store.list_gcloud_managed_accounts().unwrap().pop().unwrap();
    let pending = store.begin_gcloud_account_deletion(&account, 1).unwrap();
    store.finish_gcloud_account_deletion(&pending).unwrap();
    store.delete_generator(&key.generator_id).unwrap();
    assert!(store.has_recorded_gcloud_accounts().unwrap());
}

#[test]
fn deletion_rechecks_owner_and_lease_snapshot_then_removes_all_issued_uid_dependencies() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("profile.db")).unwrap();
    let key = key();
    let account = ready_account(&store, &key);
    let mut managed = issued_lease("active-managed", &key, ID);
    // The original request's project is not account identity evidence.
    managed.requested_generation = Some(GenerationRequest::GcloudAccess(GcloudAccessRequest {
        project_id: "requested-project".into(),
        permissions: vec![StorageRead],
    }));
    store.insert_lease(&managed).unwrap();
    assert!(store.begin_gcloud_account_deletion(&account, 1).is_err());

    let mut legacy = issued_lease("revoked-legacy", &key, ID);
    legacy.vault_id = "other-config".into();
    legacy.revoked_at = Some(2);
    legacy.generation = Some(GenerationGrant::Gcloud(asm_proto::generators::GcloudGrant {
        service_account_unique_id: ID.into(),
        service_account_email: "historical@different-project.iam.gserviceaccount.com".into(),
        scopes: vec!["https://www.googleapis.com/auth/devstorage.read_only".into()],
        project_id: Some("different-quota-project".into()),
    }));
    legacy.requested_generation = None;
    store.insert_lease(&legacy).unwrap();
    let mut expired = issued_lease("expired-managed", &key, ID);
    expired.expires_at = Some(2);
    store.insert_lease(&expired).unwrap();
    let unrelated = issued_lease("same-email-different-uid", &key, "778899");
    store.insert_lease(&unrelated).unwrap();

    let reviewed = store.gcloud_managed_account(account.id).unwrap().unwrap();
    assert_eq!(reviewed.leases.iter().map(|lease| lease.id.as_str()).collect::<Vec<_>>(),
        vec!["active-managed", "revoked-legacy", "expired-managed"]);
    assert!(store.begin_gcloud_account_deletion(&reviewed, 2).is_err());
    let mut other_owner = saved_connection(&key);
    let GeneratorConfig::GcloudConnection(config) = &mut other_owner.config else { unreachable!() };
    config.account_email = "different@example.test".into();
    store.upsert_generator(&other_owner).unwrap();
    assert!(store.begin_gcloud_account_deletion(&reviewed, 1).is_err());
    assert_eq!(store.gcloud_managed_account(account.id).unwrap(), Some(reviewed.clone()));
    store.upsert_generator(&saved_connection(&key)).unwrap();

    let pending = store.begin_gcloud_account_deletion(&reviewed, 1).unwrap();
    assert_eq!(pending.deletion, GcloudAccountDeletion::Pending);
    assert!(pending.leases.is_empty());
    assert_eq!(store.list_leases().unwrap(), vec![unrelated]);
    assert!(store.update_generated_credential(&managed.id, 1, 8).is_err());
    assert!(store.insert_lease(&legacy).is_err());
}

#[test]
fn deletion_pending_survives_restart_and_finish_releases_claims_not_the_old_uid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("profile.db");
    let key = key();
    let pending = {
        let store = Store::open(&path).unwrap();
        let account = ready_account(&store, &key);
        let pending = store.begin_gcloud_account_deletion(&account, 1).unwrap();
        assert!(store.begin_gcloud_account_deletion(&account, 1).is_err());
        pending
    };
    let store = Store::open(&path).unwrap();
    assert_eq!(store.gcloud_managed_account(pending.id).unwrap(), Some(pending.clone()));
    assert!(store.gcloud_account_is_retired(ID).unwrap());
    assert!(store.gcloud_profile(&key).is_err());
    assert!(store.begin_gcloud_profile(&key, "asm-replacement", EMAIL, None).is_err());
    assert!(store.insert_lease(&issued_lease("old-uid", &key, ID)).is_err());
    assert_eq!(store.begin_gcloud_account_deletion(&pending, 1).unwrap(), pending);

    store.finish_gcloud_account_deletion(&pending).unwrap();
    store.finish_gcloud_account_deletion(&pending).unwrap();
    let tombstone = store.gcloud_managed_account(pending.id).unwrap().unwrap();
    assert_eq!(tombstone.deletion, GcloudAccountDeletion::Deleted);
    assert_eq!(tombstone.profile, pending.profile);
    assert_eq!(store.gcloud_profile(&key).unwrap(), None);
    assert!(store.begin_gcloud_profile(&key, ACCOUNT, EMAIL, None).is_err());
    store.begin_gcloud_profile(&key, "asm-replacement", EMAIL, None).unwrap();
    assert!(store.record_gcloud_profile_identity(&key, "asm-replacement", ID).is_err());
    store.record_gcloud_profile_identity(&key, "asm-replacement", "778899").unwrap();
    assert!(!store.gcloud_account_is_retired("778899").unwrap());
    assert!(store.insert_lease(&issued_lease("old-uid", &key, ID)).is_err());
}

#[test]
fn a_failed_lease_delete_rolls_back_retirement_and_every_lease_removal() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("profile.db")).unwrap();
    let key = key();
    let account = ready_account(&store, &key);
    store.insert_lease(&issued_lease("first", &key, ID)).unwrap();
    store.insert_lease(&issued_lease("second", &key, ID)).unwrap();
    store.db().execute_batch(
        "CREATE TRIGGER abort_lease_cleanup BEFORE DELETE ON leases
         WHEN OLD.id = 'second' BEGIN SELECT RAISE(ABORT, 'cleanup failed'); END;",
    ).unwrap();
    let reviewed = store.gcloud_managed_account(account.id).unwrap().unwrap();
    assert!(store.begin_gcloud_account_deletion(&reviewed, 1).is_err());
    assert!(!store.gcloud_account_is_retired(ID).unwrap());
    assert_eq!(store.gcloud_managed_account(account.id).unwrap(), Some(reviewed));
    assert_eq!(store.gcloud_profile(&key).unwrap().unwrap().phase, GcloudProfilePhase::Ready);
}

#[test]
fn old_journal_keeps_superseded_unverified_attempt_and_verified_account() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("profile.db");
    let key = key();
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TABLE gcloud_profiles(
             generator_id TEXT NOT NULL, account_subject TEXT NOT NULL, project_id TEXT NOT NULL,
             permissions TEXT NOT NULL, account_id TEXT NOT NULL, admin_email TEXT NOT NULL,
             unique_id TEXT UNIQUE, phase INTEGER NOT NULL DEFAULT 0 CHECK (phase BETWEEN 0 AND 4),
             superseded INTEGER NOT NULL DEFAULT 0 CHECK (superseded IN (0, 1)),
             CHECK ((phase = 0 AND unique_id IS NULL) OR (phase > 0 AND unique_id IS NOT NULL)),
             CHECK (superseded = 0 OR phase = 0), PRIMARY KEY(project_id, account_id)
         );
         CREATE UNIQUE INDEX gcloud_profiles_current
             ON gcloud_profiles(generator_id, account_subject, project_id, permissions)
             WHERE superseded = 0;",
    ).unwrap();
    db.execute(
        "INSERT INTO gcloud_profiles VALUES
         (?1, ?2, ?3, ?4, ?5, ?6, NULL, 0, 1),
         (?1, ?2, ?3, ?4, 'asm-account-two', ?6, ?7, 4, 0)",
        params![key.generator_id, key.account_subject, key.access.project_id, key.permissions().unwrap(), ACCOUNT, EMAIL, ID],
    ).unwrap();
    drop(db);

    let store = Store::open(&path).unwrap();
    store.upsert_generator(&saved_connection(&key)).unwrap();
    let accounts = store.list_gcloud_managed_accounts().unwrap();
    assert_eq!(accounts.len(), 2);
    assert!(accounts[0].superseded);
    assert_eq!(accounts[0].profile.unique_id, None);
    assert_eq!(accounts[0].deletion, GcloudAccountDeletion::None);
    assert!(store.begin_gcloud_account_deletion(&accounts[0], 1).is_err());
    assert_eq!(accounts[1].profile.phase, GcloudProfilePhase::Ready);
    assert_eq!(accounts[1].profile.unique_id.as_deref(), Some(ID));
    assert_eq!(store.gcloud_profile(&key).unwrap().unwrap(), accounts[1].profile);
    let pending = store.begin_gcloud_account_deletion(&accounts[1], 1).unwrap();
    store.finish_gcloud_account_deletion(&pending).unwrap();
    store.begin_gcloud_profile(&key, "asm-replacement", EMAIL, None).unwrap();
}
