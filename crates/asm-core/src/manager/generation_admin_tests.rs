//! Administration failures use temporary SQLite and an injected, in-memory key store.
//! Issuance and revocation still go through the fixture's real local HTTP provider.
use super::*;

use asm_proto::ErrorCode;
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use std::sync::LazyLock;

#[derive(Default)]
struct Keys {
    values: Mutex<HashMap<String, String>>,
    written: Mutex<Vec<String>>,
    deleted: Mutex<Vec<String>>,
}

impl Keys {
    fn installed(ids: &[&str]) -> Self {
        Self {
            values: Mutex::new(ids.iter().map(|id| {
                ((*id).to_string(), crate::generator::github::test_pem().to_string())
            }).collect()),
            ..Self::default()
        }
    }

    fn get(&self, id: &str) -> Result<Option<String>> {
        Ok(lock(&self.values).get(id).cloned())
    }

    fn put(&self, id: &str, pem: &str) -> Result<()> {
        lock(&self.values).insert(id.to_string(), pem.to_string());
        lock(&self.written).push(id.to_string());
        Ok(())
    }

    fn delete(&self, id: &str) -> Result<()> {
        lock(&self.values).remove(id);
        lock(&self.deleted).push(id.to_string());
        Ok(())
    }

    fn save(&self, fixture: &Fixture, draft: ffi::GeneratorDraft) -> Result<ffi::GeneratorInfo> {
        fixture.core.save_generator_with_github(draft,
            |id, kind| { assert_eq!(kind, creds::GITHUB_PRIVATE_KEY); self.get(id) },
            |id, kind, pem| { assert_eq!(kind, creds::GITHUB_PRIVATE_KEY); self.put(id, pem) },
            |id, kind| { assert_eq!(kind, creds::GITHUB_PRIVATE_KEY); self.delete(id) },
            |config, pem| fixture.github_client(config, pem))
    }
}

fn replacement_pem() -> &'static str {
    static PEM: LazyLock<String> = LazyLock::new(|| {
        rsa::PrivateKey::new(&mut rand::rng(), 2048).unwrap()
            .to_pkcs1_pem(LineEnding::LF).unwrap().to_string()
    });
    PEM.as_str()
}

fn edit(f: &Fixture, id: &str) -> ffi::GeneratorDraft {
    let record = f.core.store.get_generator(id).unwrap().unwrap();
    ffi::GeneratorDraft {
        id: Some(record.id), name: record.name, config: record.config.into(),
        credentials: ffi::GeneratorCredentials::Keep,
    }
}

fn reject_generator_persistence(f: &Fixture) {
    // Fail actual writes, after credential validation/storage, without breaking
    // lease, activity, or background SQLite operations in the same fixture.
    let db = rusqlite::Connection::open(f.core.dirs.db()).unwrap();
    db.execute_batch(
        "CREATE TRIGGER generation_admin_reject_insert BEFORE INSERT ON generators
         BEGIN SELECT RAISE(ABORT, 'isolated generator persistence failure'); END;
         CREATE TRIGGER generation_admin_reject_update BEFORE UPDATE ON generators
         BEGIN SELECT RAISE(ABORT, 'isolated generator persistence failure'); END;",
    ).unwrap();
}

fn pending_choices(f: &Fixture, id: &str) -> Vec<ffi::GeneratorApprovalChoice> {
    let pending = f.core.snapshot().pending.into_iter().find(|p| p.id == id)
        .expect("request must remain pending");
    let ffi::RequestDetail::Get { generator_choices, .. } = pending.detail else {
        panic!("expected get approval");
    };
    generator_choices
}

#[test]
fn generation_admin_failed_edit_restores_key_and_preserves_live_authority() {
    let f = Fixture::new();
    let keys = Keys::installed(&["app-a"]);
    let first = f.first();
    let before = f.core.generators.get("app-a").unwrap();
    let old_client = before.client().unwrap();
    let mut draft = edit(&f, "app-a");
    draft.config = GeneratorConfig::GithubApp(GithubAppConfig {
        client_id: "replacement-client".into(), installations: vec![Fixture::grant()],
    }).into();
    draft.credentials = ffi::GeneratorCredentials::GithubPrivateKey { pem: replacement_pem().to_string() };
    reject_generator_persistence(&f);

    assert!(keys.save(&f, draft).is_err());

    assert_eq!(lock(&keys.written).as_slice(), ["app-a", "app-a"]);
    assert!(keys.get("app-a").unwrap().as_deref() == Some(crate::generator::github::test_pem()));
    assert!(lock(&keys.deleted).is_empty());
    let live = f.core.generators.get("app-a").unwrap();
    assert_eq!(live.record, before.record);
    assert!(Arc::ptr_eq(&live.client().unwrap(), &old_client));
    assert_eq!(f.core.store.get_generator("app-a").unwrap().unwrap(), before.record);
    assert_eq!(f.core.list_generators()[0].status, ffi::VaultStatus::Ready);
    assert!(f.core.store.get_lease(&first.lease_id).unwrap().unwrap().is_active(f.start));
    assert!(lock(&f.core.generation).cached.contains_key(&first.lease_id));
    assert!(lock(&f.provider.state.revoked).is_empty());

    // The preserved client must really renew against the local provider, not a
    // replacement production client or a merely preserved metadata record.
    f.at(3_000);
    let renewed = get(f.request(f.body("GITHUB_TOKEN")).unwrap());
    assert_eq!(renewed.lease_id, first.lease_id);
    assert_eq!(renewed.generation, first.generation);
    assert_eq!(renewed.expires_at, first.expires_at);
    assert_eq!(renewed.credential_version, Some(2));
    assert_eq!(f.issued(), 2);
}

#[test]
fn generation_admin_failed_key_restoration_disables_generator_and_evicts_material() {
    let f = Fixture::new();
    let keys = Keys::installed(&["app-a"]);
    let first = f.first();
    f.at(3_000);
    let current = get(f.request(f.body("GITHUB_TOKEN")).unwrap());
    let before = f.core.store.get_generator("app-a").unwrap().unwrap();
    let mut draft = edit(&f, "app-a");
    draft.credentials = ffi::GeneratorCredentials::GithubPrivateKey { pem: replacement_pem().to_string() };
    let restoration_attempts = AtomicUsize::new(0);
    reject_generator_persistence(&f);

    let saved = f.core.save_generator_with_github(draft, |id, _| keys.get(id), |id, _, pem| {
        if pem == crate::generator::github::test_pem() {
            restoration_attempts.fetch_add(1, Ordering::SeqCst);
            return Err(CoreError::internal("isolated credential restoration failure"));
        }
        keys.put(id, pem)
    }, |id, _| keys.delete(id), |config, pem| f.github_client(config, pem));
    assert!(saved.is_err());

    assert_eq!(restoration_attempts.load(Ordering::SeqCst), 1);
    assert!(keys.get("app-a").unwrap().is_none());
    assert_eq!(lock(&keys.deleted).as_slice(), ["app-a"]);
    assert_eq!(f.core.store.get_generator("app-a").unwrap().unwrap(), before);
    let live = f.core.generators.get("app-a").unwrap();
    assert_eq!(live.record, before);
    assert!(live.generator.is_none());
    assert!(matches!(&f.core.list_generators()[0].status,
        ffi::VaultStatus::Error { message } if message.contains("rollback failed")));
    assert!(!lock(&f.core.generation).cached.contains_key(&first.lease_id));
    assert!(!lock(&f.core.generation).retired_only.contains_key(&first.lease_id));
    assert!(!lock(&f.core.proxy_state).entries.contains_key(&first.lease_id));
    let revoked = lock(&f.provider.state.revoked).clone();
    assert_eq!(revoked.len(), 2);
    assert!(revoked.contains(&first.files[0].content));
    assert!(revoked.contains(&current.files[0].content));

    let mut pinned = f.body("GITHUB_TOKEN");
    if let RequestBody::Get { lease_id, .. } = &mut pinned {
        *lease_id = Some(first.lease_id.clone());
    }
    assert_eq!(f.request(pinned).unwrap_err().code, ErrorCode::VaultUnavailable);
    assert_eq!(f.issued(), 2);
    assert!(f.core.store.get_lease(&first.lease_id).unwrap().unwrap().is_active(f.start + 3_000));
}

#[test]
fn generation_admin_display_rename_preserves_client_revision_and_lease() {
    let f = Fixture::new();
    let keys = Keys::installed(&["app-a"]);
    let first = f.first();
    let before = f.core.generators.get("app-a").unwrap();
    let old_client = before.client().unwrap();
    let old_lease = f.core.store.get_lease(&first.lease_id).unwrap().unwrap();
    let mut draft = edit(&f, "app-a");
    draft.name = "renamed-bot".into();

    let saved = keys.save(&f, draft).unwrap();

    assert_eq!(saved.name, "renamed-bot");
    assert_eq!(saved.revision, 1);
    assert_eq!(saved.status, ffi::VaultStatus::Ready);
    let live = f.core.generators.get("app-a").unwrap();
    assert_eq!(live.record.id, "app-a");
    assert_eq!(live.record.config, before.record.config);
    assert_eq!(live.record.revision, before.record.revision);
    assert!(Arc::ptr_eq(&live.client().unwrap(), &old_client));
    assert_eq!(f.core.store.get_generator("app-a").unwrap().unwrap(), live.record);
    assert!(lock(&keys.written).is_empty());
    assert!(lock(&keys.deleted).is_empty());
    assert!(keys.get("app-a").unwrap().as_deref() == Some(crate::generator::github::test_pem()));
    let lease = f.core.store.get_lease(&first.lease_id).unwrap().unwrap();
    assert_eq!(lease.created_at, old_lease.created_at);
    assert_eq!(lease.expires_at, old_lease.expires_at);
    assert_eq!(lease.fields, old_lease.fields);
    assert_eq!(lease.approval_order, old_lease.approval_order);
    assert_eq!(lease.generator_revision, Some(1));
    assert!(lease.is_active(f.start));
    assert!(lock(&f.provider.state.revoked).is_empty());
    let reused = get(f.request(f.body("GITHUB_TOKEN")).unwrap());
    assert_eq!(reused.lease_id, first.lease_id);
    assert_eq!(reused.files, first.files);
    assert_eq!(f.issued(), 1);

    // Exact-lease renewal accepts the current qualified alias after the rename.
    f.at(3_000);
    let mut pinned = f.body("renamed-bot/GITHUB_TOKEN");
    if let RequestBody::Get { lease_id, .. } = &mut pinned {
        *lease_id = Some(first.lease_id.clone());
    }
    let renewed = get(f.request(pinned).unwrap());
    assert_eq!(renewed.lease_id, first.lease_id);
    assert_eq!(renewed.generation, first.generation);
    assert_eq!(renewed.expires_at, first.expires_at);
    assert_eq!(renewed.credential_version, Some(2));
    assert_eq!(f.issued(), 2);
}

#[test]
fn generation_admin_pending_edits_refresh_offered_revisions_without_adding_sources() {
    let f = Fixture::new();
    f.install("app-b", "review-bot", 2);
    let keys = Keys::installed(&["app-a", "app-b"]);
    let group = f.request(f.body("GH_TOKEN")).unwrap();
    let pinned = f.request(f.body("release-bot/GITHUB_TOKEN")).unwrap();
    let initial = pending_choices(&f, &group.request_id);
    assert_eq!(initial.iter().map(|c| c.choice.generator_id.as_str()).collect::<Vec<_>>(), ["app-a", "app-b"]);
    assert!(initial[0].scope_issues.is_empty());
    f.install("app-c", "later-bot", 3);
    let mut ceiling = Fixture::grant();
    ceiling.permissions.insert("contents".into(), GithubPermission::Write);
    let mut draft = edit(&f, "app-a");
    draft.name = "edited-bot".into();
    draft.config = GeneratorConfig::GithubApp(GithubAppConfig {
        client_id: "edited-client".into(), installations: vec![ceiling],
    }).into();

    let saved = keys.save(&f, draft).unwrap();

    assert_eq!(saved.revision, 2);
    assert!(lock(&keys.written).is_empty());
    let choices = pending_choices(&f, &group.request_id);
    assert_eq!(choices.iter().map(|c| c.choice.generator_id.as_str()).collect::<Vec<_>>(), ["app-a", "app-b"]);
    assert_eq!(choices[0].choice.name, "edited-bot");
    assert_eq!(choices[0].choice.revision, 2);
    assert_eq!(choices[0].choice.ceiling, ffi::GenerationGrant::from(GenerationGrant::GithubApp(Fixture::grant())));
    assert!(choices[0].choice.available);
    assert!(choices[0].scope_issues.is_empty());
    assert_eq!(choices[1].choice.revision, 1);
    assert!(choices[1].scope_issues.is_empty());
    let pinned_choices = pending_choices(&f, &pinned.request_id);
    assert_eq!(pinned_choices.len(), 1);
    assert_eq!(pinned_choices[0].choice.generator_id, "app-a");
    assert_eq!(pinned_choices[0].choice.revision, 2);
    assert_eq!(f.approve(&group.request_id, "app-a", LeaseMode::Raw, 43_200).unwrap_err().code, ErrorCode::Invalid);
    assert_eq!(f.approve(&group.request_id, "app-c", LeaseMode::Raw, 43_200).unwrap_err().code, ErrorCode::Invalid);
    assert_eq!(f.issued(), 0);
    assert_eq!(f.core.request_state(&f.host.id, &group.request_id).unwrap().status, RequestStatus::Pending);

    // Operator choice among overlapping installations of different generators is preserved.
    f.approve(&group.request_id, "app-b", LeaseMode::Raw, 43_200).unwrap();
    let approved = get(f.core.request_state(&f.host.id, &group.request_id).unwrap());
    assert_eq!(approved.generation.unwrap().generator_id, "app-b");
    assert_eq!(f.issued(), 1);
}

#[test]
fn generation_admin_removing_one_installation_ends_its_pending_request() {
    let f = Fixture::new();
    let mut removed = Fixture::grant();
    removed.installation_id = 8;
    removed.repositories = vec![GithubRepository { id: 3, full_name: "acme/repo3".into() }];
    f.install_with_ceilings("app-b", "review-bot", 2, vec![Fixture::grant(), removed.clone()]);
    let mut body = f.body("review-bot/GH_TOKEN");
    if let RequestBody::Get { generation: Some(GenerationRequest::GithubApp(scope)), .. } = &mut body {
        scope.repositories = Some(vec!["acme/repo3".into()]);
    }
    let pending = f.request(body).unwrap();
    let choices = pending_choices(&f, &pending.request_id);
    assert_eq!(choices.len(), 1);
    assert_eq!(choices[0].choice.ceiling, ffi::GenerationGrant::from(GenerationGrant::GithubApp(removed.clone())));
    let keys = Keys::installed(&["app-b"]);
    let mut draft = edit(&f, "app-b");
    draft.config = GeneratorConfig::GithubApp(GithubAppConfig {
        client_id: "client-app-b".into(), installations: vec![Fixture::grant()],
    }).into();
    assert_eq!(keys.save(&f, draft).unwrap().revision, 2);

    let denied = f.core.request_state(&f.host.id, &pending.request_id).unwrap();
    assert_eq!(denied.status, RequestStatus::Denied);
    assert!(f.approve_github(&pending.request_id, "app-b", 1, removed, LeaseMode::Raw, 43_200).is_err());
    assert_eq!(f.issued(), 0);
}

#[test]
fn generation_admin_removal_denies_empty_offers_without_rebinding_new_sources() {
    let f = Fixture::new();
    f.install("app-b", "review-bot", 2);
    let keys = Keys::installed(&["app-a", "app-b", "app-c"]);
    let group = f.request(f.body("GH_TOKEN")).unwrap();
    let pinned = f.request(f.body("release-bot/GITHUB_TOKEN")).unwrap();
    f.install("app-c", "later-bot", 3);

    f.core.remove_generator_with("app-a", |id, kind| {
        assert_eq!(kind, creds::GITHUB_PRIVATE_KEY);
        keys.delete(id)
    }).unwrap();

    let remaining = pending_choices(&f, &group.request_id);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].choice.generator_id, "app-b");
    let ended = f.core.request_state(&f.host.id, &pinned.request_id).unwrap();
    assert_eq!(ended.status, RequestStatus::Denied);
    assert!(ended.result.is_none());
    assert_eq!(ended.deny_reason.as_deref(), Some(crate::error::REQUEST_UNAVAILABLE));
    assert!(!f.core.snapshot().pending.iter().any(|p| p.id == pinned.request_id));
    assert!(keys.get("app-a").unwrap().is_none());
    assert!(f.core.store.get_generator("app-a").unwrap().is_none());

    f.core.remove_generator_with("app-b", |id, kind| {
        assert_eq!(kind, creds::GITHUB_PRIVATE_KEY);
        keys.delete(id)
    }).unwrap();

    let ended = f.core.request_state(&f.host.id, &group.request_id).unwrap();
    assert_eq!(ended.status, RequestStatus::Denied);
    assert!(ended.result.is_none());
    assert_eq!(ended.deny_reason.as_deref(), Some(crate::error::REQUEST_UNAVAILABLE));
    assert!(f.core.snapshot().pending.is_empty());
    assert!(f.approve(&group.request_id, "app-c", LeaseMode::Raw, 43_200).is_err());
    assert_eq!(f.core.list_generators().iter().map(|g| g.id.as_str()).collect::<Vec<_>>(), ["app-c"]);
    assert_eq!(lock(&keys.deleted).as_slice(), ["app-a", "app-b"]);
    assert!(keys.get("app-b").unwrap().is_none());
    assert!(keys.get("app-c").unwrap().is_some());
    assert_eq!(f.issued(), 0);
}

#[test]
fn generation_admin_failed_new_save_deletes_only_the_new_credential() {
    let f = Fixture::new();
    let keys = Keys::installed(&["app-a"]);
    let before = f.core.generators.get("app-a").unwrap();
    let old_client = before.client().unwrap();
    let draft = ffi::GeneratorDraft {
        id: None, name: "new-bot".into(),
        config: GeneratorConfig::GithubApp(GithubAppConfig {
            client_id: "new-client".into(), installations: vec![Fixture::grant()],
        }).into(),
        credentials: ffi::GeneratorCredentials::GithubPrivateKey { pem: replacement_pem().to_string() },
    };
    reject_generator_persistence(&f);

    assert!(keys.save(&f, draft).is_err());

    let written = lock(&keys.written).clone();
    assert_eq!(written.len(), 1);
    assert_ne!(written[0], "app-a");
    assert_eq!(*lock(&keys.deleted), written);
    assert_eq!(lock(&keys.values).len(), 1);
    assert!(keys.get("app-a").unwrap().as_deref() == Some(crate::generator::github::test_pem()));
    assert_eq!(f.core.generators.entries().len(), 1);
    let live = f.core.generators.get("app-a").unwrap();
    assert_eq!(live.record, before.record);
    assert!(Arc::ptr_eq(&live.client().unwrap(), &old_client));
    assert_eq!(f.core.store.list_generators().unwrap(), vec![before.record]);
    assert!(f.core.store.list_leases().unwrap().is_empty());
    assert_eq!(f.issued(), 0);
}

#[test]
fn generation_admin_invalid_github_key_is_never_written() {
    let f = Fixture::new();
    let mut draft = edit(&f, "app-a");
    draft.credentials = ffi::GeneratorCredentials::GithubPrivateKey { pem: "not a PEM key".into() };
    assert!(f.core.save_generator_with(draft, |_, _| Ok(None),
        |_, _, _| panic!("invalid private key must not be stored"),
        |_, _| panic!("invalid private key must not require rollback")).is_err());
    assert_eq!(f.core.list_generators()[0].revision, 1);
}

#[test]
fn generation_admin_google_cancelled_reconnect_preserves_offline_rename_and_active_lease() {
    let f = Fixture::new();
    let config = f.install_gcloud();
    let pending = f.request(f.body(GCLOUD_TOKEN_NAME)).unwrap();
    f.approve_gcloud(&pending.request_id).unwrap();
    let first = get(f.core.request_state(&f.host.id, &pending.request_id).unwrap());
    let before = f.core.generators.get(GCLOUD_ID).unwrap();
    let old_client = before.client().unwrap();
    let mut draft = edit(&f, GCLOUD_ID);
    draft.name = "cloud-renamed".into();
    let get_key = |id: &str, kind: &str| {
        assert_eq!((id, kind), (GCLOUD_ID, creds::GCLOUD_ADC));
        Ok(Some(GCLOUD_ADC_FIXTURE.into()))
    };
    let reject_put = |_: &str, _: &str, _: &str| -> Result<()> { panic!("offline edits must not write a credential") };
    let reject_delete = |_: &str, _: &str| -> Result<()> { panic!("offline edits must not delete a credential") };
    let mut new_legacy = draft.clone();
    new_legacy.id = None;
    assert!(f.core.save_generator_with(new_legacy,
        |_, _| panic!("new legacy generator must be rejected before keychain access"),
        reject_put, reject_delete).is_err());
    assert!(f.core.save_generator_with(draft.clone(), |_, _| Ok(None), reject_put, reject_delete).is_err());
    let sdk_path = config.sdk_path;
    let session_id = f.core.gcloud_begin_login(sdk_path).unwrap();
    f.core.gcloud_cancel_login(&session_id).unwrap();
    let mut cancelled = draft.clone();
    cancelled.credentials = ffi::GeneratorCredentials::GcloudSession { session_id };
    assert!(f.core.save_generator_with(cancelled, get_key, reject_put, reject_delete).is_err());
    assert_eq!(f.core.generators.get(GCLOUD_ID).unwrap().record, before.record);

    // An untrusted legacy draft cannot widen its saved scopes or move targets.
    let ffi::GeneratorConfig::Gcloud { config: submitted } = &mut draft.config else {
        panic!("expected legacy config");
    };
    submitted.project_id = "different-project".into();
    submitted.ceiling.scopes.push("https://www.googleapis.com/auth/compute".into());
    let saved = f.core.save_generator_with(draft, get_key, reject_put, reject_delete).unwrap();
    assert_eq!(saved.name, "cloud-renamed");
    assert_eq!(saved.revision, first.generation.as_ref().unwrap().generator_revision);
    assert_eq!(saved.config, before.record.config.clone().into());
    assert!(Arc::ptr_eq(&f.core.generators.get(GCLOUD_ID).unwrap().client().unwrap(), &old_client));
    let mut pinned = f.body("cloud-renamed/CLOUDSDK_AUTH_ACCESS_TOKEN");
    if let RequestBody::Get { lease_id, .. } = &mut pinned { *lease_id = Some(first.lease_id.clone()); }
    let reused = get(f.request(pinned.clone()).unwrap());
    assert_eq!(reused.lease_id, first.lease_id);
    assert_eq!(reused.files, first.files);
    if let RequestBody::Get { generation, .. } = &mut pinned {
        *generation = Some(GenerationRequest::GithubApp(GithubScopeRequest::default()));
    }
    assert_eq!(f.request(pinned).unwrap_err().code, ErrorCode::Invalid);
    assert_eq!(f.issued(), 1);
}

#[test]
fn generation_admin_google_reconnect_rolls_back_adc_then_replaces_only_on_commit() {
    use crate::generator::gcloud::GcloudIdentity;

    let f = Fixture::new();
    let mut config = f.install_gcloud();
    let pending = f.request(f.body(GCLOUD_TOKEN_NAME)).unwrap();
    f.approve_gcloud(&pending.request_id).unwrap();
    let first = get(f.core.request_state(&f.host.id, &pending.request_id).unwrap());
    let before = f.core.generators.get(GCLOUD_ID).unwrap();
    let old_client = before.client().unwrap();
    let adc = GCLOUD_ADC_FIXTURE.replace("isolated-refresh-token", "reconnected-refresh-token");
    f.core.set_gcloud_setup_endpoint_for_test(f.provider.url.clone()).unwrap();
    let session_id = f.core.install_gcloud_setup_for_test(config.sdk_path.clone().into(), &adc,
        GcloudIdentity { subject: config.account_subject.clone(), email: config.account_email.clone() },
    ).unwrap();
    config.project_number = "999999".into(); // Untrusted draft metadata is not authority.
    let draft = ffi::GeneratorDraft { id: Some(GCLOUD_ID.into()), name: "cloud-dev".into(),
        config: GeneratorConfig::Gcloud(config).into(),
        credentials: ffi::GeneratorCredentials::GcloudSession { session_id: session_id.clone() } };
    let db_material = Mutex::new(GCLOUD_ADC_FIXTURE.to_string());
    let writes = AtomicUsize::new(0);
    let save = |draft| f.core.save_generator_with(draft, |id, kind| {
        assert_eq!((id, kind), (GCLOUD_ID, creds::GCLOUD_ADC));
        Ok(Some(lock(&db_material).clone()))
    }, |id, kind, adc| {
        assert_eq!((id, kind), (GCLOUD_ID, creds::GCLOUD_ADC));
        *lock(&db_material) = adc.to_owned();
        writes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }, |_, _| panic!("an existing ADC must be restored, not deleted"));

    reject_generator_persistence(&f);
    assert!(save(draft.clone()).is_err());
    assert_eq!(writes.load(Ordering::SeqCst), 2, "new ADC and exact old ADC rollback");
    assert_eq!(lock(&db_material).as_str(), GCLOUD_ADC_FIXTURE);
    assert!(Arc::ptr_eq(&f.core.generators.get(GCLOUD_ID).unwrap().client().unwrap(), &old_client));
    assert_eq!(f.core.store.get_generator(GCLOUD_ID).unwrap().unwrap(), before.record);
    assert!(f.core.check_generated_delivery(&first.lease_id, 1).is_ok());

    let db = rusqlite::Connection::open(f.core.dirs.db()).unwrap();
    db.execute_batch("DROP TRIGGER generation_admin_reject_insert; DROP TRIGGER generation_admin_reject_update;").unwrap();
    let saved = save(draft).unwrap();
    assert_eq!(saved.revision, 2);
    assert_eq!(writes.load(Ordering::SeqCst), 3);
    f.core.mark_gcloud_sign_in_required(GCLOUD_ID, saved.revision, &old_client);
    assert!(f.core.generators.get(GCLOUD_ID).unwrap().client().is_ok(),
        "a failure from a retired client must not mark its replacement unavailable");
    assert!(lock(&db_material).contains("reconnected-refresh-token"));
    let GeneratorConfig::Gcloud(stored) = f.core.store.get_generator(GCLOUD_ID).unwrap().unwrap().config else {
        panic!("expected a saved Google configuration");
    };
    assert_eq!(stored.project_number, "123456");
    assert!(f.core.gcloud_finish_login(&session_id).is_err(), "completed sign-in is single-use after commit");
    assert!(f.core.check_generated_delivery(&first.lease_id, 1).is_err());
    assert_eq!(generator_activity(&f).iter().filter(|r| r.kind == "revocation_unsupported").count(), 1);
    assert!(!format!("{:?}", f.core.list_generators()).contains("refresh-token"));
    for path in [f.core.dirs.db(), f.core.dirs.db().with_extension("db-wal")] {
        if path.exists() {
            let bytes = std::fs::read(path).unwrap();
            for secret in ["isolated-refresh-token", "reconnected-refresh-token", first.files[0].content.as_str()] {
                assert!(!bytes.windows(secret.len()).any(|window| window == secret.as_bytes()));
            }
        }
    }
}

#[test]
fn generation_admin_cloud_connection_saves_completed_login_without_project_and_renames_offline() {
    use crate::generator::gcloud::GcloudIdentity;
    use std::os::unix::fs::PermissionsExt;

    let f = Fixture::new();
    let sdk = f._tmp.path().canonicalize().unwrap().join("gcloud");
    std::fs::write(&sdk, format!(r#"#!/bin/sh
case "$1:$2:$3" in
  version:*) printf '%s\n' '{{"Google Cloud SDK":"582.0.0"}}' ;;
  auth:application-default:login)
    [ "$4" = --launch-browser ] && [ "$5" = --disable-quota-project ] &&
    [ -z "${{GOOGLE_APPLICATION_CREDENTIALS-}}" ] || exit 7
    printf '%s\n' '{GCLOUD_ADC_FIXTURE}' > "$CLOUDSDK_CONFIG/application_default_credentials.json" ;;
  auth:application-default:print-access-token)
    [ "$#" -eq 5 ] && [ -f "$GOOGLE_APPLICATION_CREDENTIALS" ] || exit 7
    printf 'isolated-parent\n' ;;
  *) exit 7 ;;
esac
"#)).unwrap();
    std::fs::set_permissions(&sdk, std::fs::Permissions::from_mode(0o700)).unwrap();
    f.core.set_gcloud_setup_endpoint_for_test(f.provider.url.clone()).unwrap();
    let session_id = f.core.gcloud_begin_login(sdk.to_str().unwrap().into()).unwrap();
    let identity = f.core.gcloud_finish_login(&session_id).unwrap();
    assert_eq!(identity.subject, "90001");
    let keys = Keys::default();
    let mut draft = ffi::GeneratorDraft {
        id: None,
        name: "managed-cloud".into(),
        config: GeneratorConfig::GcloudConnection(GcloudConnectionConfig {
            sdk_path: "/unverified/gcloud".into(),
            account_subject: "unverified".into(),
            account_email: "unverified@example.test".into(),
        }).into(),
        credentials: ffi::GeneratorCredentials::GcloudSession { session_id: session_id.clone() },
    };
    let save = |draft| f.core.save_generator_with(draft,
        |id, kind| { assert_eq!(kind, creds::GCLOUD_ADC); keys.get(id) },
        |id, kind, adc| { assert_eq!(kind, creds::GCLOUD_ADC); keys.put(id, adc) },
        |id, kind| { assert_eq!(kind, creds::GCLOUD_ADC); keys.delete(id) });
    let mut missing_sign_in = draft.clone();
    missing_sign_in.credentials = ffi::GeneratorCredentials::Keep;
    assert!(save(missing_sign_in).is_err());
    reject_generator_persistence(&f);
    assert!(save(draft.clone()).is_err());
    let abandoned = lock(&keys.written)[0].clone();
    assert_eq!(lock(&keys.deleted).as_slice(), &[abandoned.clone()]);
    assert!(keys.get(&abandoned).unwrap().is_none());
    assert!(f.core.gcloud_finish_login(&session_id).is_ok(), "failed DB writes must not consume the login");
    rusqlite::Connection::open(f.core.dirs.db()).unwrap()
        .execute_batch("DROP TRIGGER generation_admin_reject_insert; DROP TRIGGER generation_admin_reject_update;")
        .unwrap();
    let saved = save(draft.clone()).unwrap();
    assert_eq!(saved.revision, 1);
    let before = f.core.generators.get(&saved.id).unwrap();
    let GeneratorConfig::GcloudConnection(config) = &before.record.config else {
        panic!("expected sign-in-only configuration");
    };
    assert_eq!(config.sdk_path, sdk.to_str().unwrap());
    assert_eq!(config.account_subject, identity.subject);
    assert_eq!(config.account_email, identity.email);
    assert!(keys.get(&saved.id).unwrap().unwrap().contains("isolated-refresh-token"));
    assert!(f.core.gcloud_finish_login(&session_id).is_err());
    assert_eq!(f.provider.state.google_calls.load(Ordering::SeqCst), 1, "only userinfo, no project lookup or IAM");
    assert_eq!(f.issued(), 0);

    // A same-email login with a different immutable subject cannot replace ADC.
    let wrong_session = f.core.install_gcloud_setup_for_test(sdk.clone(), GCLOUD_ADC_FIXTURE,
        GcloudIdentity { subject: "different-subject".into(), email: identity.email.clone() }).unwrap();
    draft.id = Some(saved.id.clone());
    draft.credentials = ffi::GeneratorCredentials::GcloudSession { session_id: wrong_session };
    assert!(save(draft.clone()).unwrap_err().message.contains("account already connected"));
    assert_eq!(f.core.store.get_generator(&saved.id).unwrap().unwrap(), before.record);

    draft.credentials = ffi::GeneratorCredentials::Keep;
    draft.name = "managed-cloud-renamed".into();
    let renamed = save(draft.clone()).unwrap();
    assert_eq!(renamed.name, "managed-cloud-renamed");
    assert_eq!(renamed.revision, 1);
    assert_eq!(renamed.config, saved.config);
    assert_eq!(lock(&keys.written).as_slice(), &[abandoned, saved.id.clone()]);
    let live = f.core.generators.get(&saved.id).unwrap();
    assert!(Arc::ptr_eq(&live.client().unwrap(), &before.client().unwrap()));
    assert_eq!(f.provider.state.google_calls.load(Ordering::SeqCst), 1);

    // Explicit reauthorization installs a fresh client and revision even if
    // Google returns the same ADC fields, without another keychain write.
    let old_client = live.client().unwrap();
    f.core.mark_gcloud_sign_in_required(&saved.id, renamed.revision, &old_client);
    let reconnected = f.core.install_gcloud_setup_for_test(sdk, GCLOUD_ADC_FIXTURE, identity).unwrap();
    draft.credentials = ffi::GeneratorCredentials::GcloudSession { session_id: reconnected };
    let reconnected = save(draft).unwrap();
    assert_eq!(reconnected.revision, 2);
    assert_eq!(reconnected.status, ffi::VaultStatus::Ready);
    assert_eq!(lock(&keys.written).len(), 2);
}
