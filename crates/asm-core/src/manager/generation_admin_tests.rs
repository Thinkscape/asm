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

    fn save(&self, core: &Core, draft: ffi::GeneratorDraft) -> Result<ffi::GeneratorInfo> {
        core.save_generator_with(draft,
            |id| self.get(id), |id, pem| self.put(id, pem), |id| self.delete(id))
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
        private_key_pem: String::new(),
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
        client_id: "replacement-client".into(), installation_id: 7, ceiling: Fixture::grant(),
    }).into();
    draft.private_key_pem = replacement_pem().to_string();
    reject_generator_persistence(&f);

    assert!(keys.save(&f.core, draft).is_err());

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
    draft.private_key_pem = replacement_pem().to_string();
    let restoration_attempts = AtomicUsize::new(0);
    reject_generator_persistence(&f);

    let saved = f.core.save_generator_with(draft, |id| keys.get(id), |id, pem| {
        if pem == crate::generator::github::test_pem() {
            restoration_attempts.fetch_add(1, Ordering::SeqCst);
            return Err(CoreError::internal("isolated credential restoration failure"));
        }
        keys.put(id, pem)
    }, |id| keys.delete(id));
    assert!(saved.is_err());

    assert_eq!(restoration_attempts.load(Ordering::SeqCst), 1);
    assert!(keys.get("app-a").unwrap().as_deref() == Some(replacement_pem()));
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

    let saved = keys.save(&f.core, draft).unwrap();

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
    let mut body = f.body("GH_TOKEN");
    if let RequestBody::Get { generation, .. } = &mut body {
        *generation = Some(GenerationRequest::GithubApp(GithubScopeRequest {
            repositories: Some(vec!["acme/repo1".into()]),
            permissions: Some([("contents".into(), GithubPermission::Write)].into_iter().collect()),
        }));
    }
    let group = f.request(body).unwrap();
    let pinned = f.request(f.body("release-bot/GITHUB_TOKEN")).unwrap();
    let initial = pending_choices(&f, &group.request_id);
    assert_eq!(initial.iter().map(|c| c.choice.generator_id.as_str()).collect::<Vec<_>>(), ["app-a", "app-b"]);
    assert!(!initial[0].scope_issues.is_empty());
    f.install("app-c", "later-bot", 3);
    let mut ceiling = Fixture::grant();
    ceiling.permissions.insert("contents".into(), GithubPermission::Write);
    let mut draft = edit(&f, "app-a");
    draft.name = "edited-bot".into();
    draft.config = GeneratorConfig::GithubApp(GithubAppConfig {
        client_id: "edited-client".into(), installation_id: 7, ceiling: ceiling.clone(),
    }).into();

    let saved = keys.save(&f.core, draft).unwrap();

    assert_eq!(saved.revision, 2);
    assert!(lock(&keys.written).is_empty());
    let choices = pending_choices(&f, &group.request_id);
    assert_eq!(choices.iter().map(|c| c.choice.generator_id.as_str()).collect::<Vec<_>>(), ["app-a", "app-b"]);
    assert_eq!(choices[0].choice.name, "edited-bot");
    assert_eq!(choices[0].choice.revision, 2);
    assert_eq!(choices[0].choice.ceiling, ffi::GenerationGrant::from(GenerationGrant::GithubApp(ceiling)));
    assert!(choices[0].choice.available);
    assert!(choices[0].scope_issues.is_empty());
    assert_eq!(choices[1].choice.revision, 1);
    assert!(!choices[1].scope_issues.is_empty());
    let pinned_choices = pending_choices(&f, &pinned.request_id);
    assert_eq!(pinned_choices.len(), 1);
    assert_eq!(pinned_choices[0].choice.generator_id, "app-a");
    assert_eq!(pinned_choices[0].choice.revision, 2);
    assert_eq!(f.approve(&group.request_id, "app-c", LeaseMode::Raw, 43_200).unwrap_err().code, ErrorCode::Invalid);
    assert_eq!(f.issued(), 0);
    assert_eq!(f.core.request_state(&f.host.id, &group.request_id).unwrap().status, RequestStatus::Pending);

    // A still-offered local provider can satisfy a deliberate narrower approval.
    f.approve(&group.request_id, "app-b", LeaseMode::Raw, 43_200).unwrap();
    let approved = get(f.core.request_state(&f.host.id, &group.request_id).unwrap());
    assert_eq!(approved.generation.unwrap().generator_id, "app-b");
    assert_eq!(f.issued(), 1);
}

#[test]
fn generation_admin_removal_denies_empty_offers_without_rebinding_new_sources() {
    let f = Fixture::new();
    f.install("app-b", "review-bot", 2);
    let keys = Keys::installed(&["app-a", "app-b", "app-c"]);
    let group = f.request(f.body("GH_TOKEN")).unwrap();
    let pinned = f.request(f.body("release-bot/GITHUB_TOKEN")).unwrap();
    f.install("app-c", "later-bot", 3);

    f.core.remove_generator_with("app-a", |id| keys.delete(id)).unwrap();

    let remaining = pending_choices(&f, &group.request_id);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].choice.generator_id, "app-b");
    let ended = f.core.request_state(&f.host.id, &pinned.request_id).unwrap();
    assert_eq!(ended.status, RequestStatus::Denied);
    assert!(ended.result.is_none());
    assert!(ended.deny_reason.unwrap().contains("no offered generators remain"));
    assert!(!f.core.snapshot().pending.iter().any(|p| p.id == pinned.request_id));
    assert!(keys.get("app-a").unwrap().is_none());
    assert!(f.core.store.get_generator("app-a").unwrap().is_none());

    f.core.remove_generator_with("app-b", |id| keys.delete(id)).unwrap();

    let ended = f.core.request_state(&f.host.id, &group.request_id).unwrap();
    assert_eq!(ended.status, RequestStatus::Denied);
    assert!(ended.result.is_none());
    assert!(ended.deny_reason.unwrap().contains("no offered generators remain"));
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
            client_id: "new-client".into(), installation_id: 7, ceiling: Fixture::grant(),
        }).into(),
        private_key_pem: replacement_pem().to_string(),
    };
    reject_generator_persistence(&f);

    assert!(keys.save(&f.core, draft).is_err());

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
