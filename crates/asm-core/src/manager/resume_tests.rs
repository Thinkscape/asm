use rusqlite::{Connection, params};
use tempfile::tempdir;

use super::*;
use crate::store::HistoryRecord;

const TEST_KEY: [u8; 32] = [0x57; 32];

#[test]
fn encrypted_rows_survive_reopen_and_get_a_fresh_nonce_on_each_write() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("asm.db");
    let store = Arc::new(Store::open(&path).unwrap());
    let resume = ResumeStore::open(store.clone(), Some(TEST_KEY)).unwrap();
    let value = "unique-sensitive-value-for-restart-sentinel-fixture".to_owned();
    resume.put("tokens", "lease-a", &value).unwrap();
    let first = store.get_resume("tokens", "lease-a").unwrap().unwrap();
    resume.put("tokens", "lease-a", &value).unwrap();
    let second = store.get_resume("tokens", "lease-a").unwrap().unwrap();
    assert_ne!(&first[..NONCE_LEN], &second[..NONCE_LEN]);
    drop(resume);
    drop(store);

    assert!(!std::fs::read(&path).unwrap().windows(value.len()).any(|w| w == value.as_bytes()));
    let store = Arc::new(Store::open(&path).unwrap());
    let resume = ResumeStore::open(store, Some(TEST_KEY)).unwrap();
    assert_eq!(resume.get::<String>("tokens", "lease-a").unwrap().as_ref(), Some(&value));
    assert_eq!(resume.list::<String>("tokens").unwrap(), [("lease-a".into(), value)]);
    resume.remove("tokens", "lease-a").unwrap();
    assert_eq!(resume.get::<String>("tokens", "lease-a").unwrap(), None);
}

#[test]
fn cannot_move_ciphertext_between_namespaces_ids_or_databases() {
    let dir = tempdir().unwrap();
    let origin = dir.path().join("origin.db");
    let target = dir.path().join("target.db");
    let first = Arc::new(Store::open(&origin).unwrap());
    let resume = ResumeStore::open(first.clone(), Some(TEST_KEY)).unwrap();
    resume.put("a", "bc", &"sensitive").unwrap();
    let sealed = first.get_resume("a", "bc").unwrap().unwrap();

    let raw = Connection::open(&origin).unwrap();
    for (namespace, id) in [("other", "bc"), ("a", "other"), ("ab", "c")] {
        raw.execute("INSERT INTO resume_entries VALUES (?1, ?2, ?3)", params![namespace, id, sealed]).unwrap();
        assert!(resume.get::<String>(namespace, id).is_err());
    }
    assert!(resume.list::<String>("a").is_err());
    let second = Arc::new(Store::open(&target).unwrap());
    let resume = ResumeStore::open(second, Some(TEST_KEY)).unwrap();
    Connection::open(&target).unwrap().execute(
        "INSERT INTO resume_entries VALUES ('a', 'bc', ?1)", [&sealed],
    ).unwrap();
    assert!(resume.get::<String>("a", "bc").is_err());
}

#[test]
fn missing_or_wrong_key_never_reinitializes_a_committed_database() {
    let dir = tempdir().unwrap();
    let store = Arc::new(Store::open(&dir.path().join("asm.db")).unwrap());
    let resume = ResumeStore::open(store.clone(), Some(TEST_KEY)).unwrap();
    // Even an identity with no user rows authenticates the original key.
    assert!(ResumeStore::open(store.clone(), Some([0x89; 32])).is_err());
    let missing = ResumeStore::open_with_key(store.clone(), |_, creating| {
        assert!(!creating, "never replace an existing restart key");
        Err(CoreError::internal("test key missing"))
    });
    assert!(matches!(missing, Err(e) if e.message == "test key missing"));
    // Failed opens cannot claim writer ownership or move existing data.
    resume.put("tokens", "lease", &"original").unwrap();
    let reopened = ResumeStore::open(store, Some(TEST_KEY)).unwrap();
    assert_eq!(reopened.get::<String>("tokens", "lease").unwrap().as_deref(), Some("original"));
}

#[test]
fn key_creation_failure_does_not_commit_a_database_identity() {
    let dir = tempdir().unwrap();
    let store = Arc::new(Store::open(&dir.path().join("asm.db")).unwrap());
    let unavailable = ResumeStore::open_with_key(store.clone(), |_, creating| {
        assert!(creating);
        Err(CoreError::internal("test keychain locked"))
    });
    assert!(unavailable.is_err());
    let available = ResumeStore::open_with_key(store, |_, creating| {
        assert!(creating);
        make_key(&TEST_KEY)
    });
    assert!(available.is_ok());
}

#[test]
fn closing_or_reopening_fences_prepared_writes_and_joined_request_history() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("asm.db");
    let original_store = Arc::new(Store::open(&path).unwrap());
    let original = ResumeStore::open(original_store.clone(), Some(TEST_KEY)).unwrap();
    original.put("requests", "request", &"before-close").unwrap();
    let sealed = original.seal("requests", "request", &"after-close").unwrap();
    let store = Arc::new(Store::open(&path).unwrap());
    let reopened = ResumeStore::open(store.clone(), Some(TEST_KEY)).unwrap();
    assert!(original.remove("requests", "request").is_err());
    original.close().unwrap(); // A stale close must not relinquish the new writer.
    let history = HistoryRecord {
        id: "request".into(),
        kind: "get".into(),
        host_id: None,
        host_label: "host".into(),
        summary: "get name".into(),
        status: "approved".into(),
        deny_reason: None,
        created_at: 1,
        resolved_at: 2,
    };
    assert!(original_store.commit_request_book(&[sealed], Some(&history)).is_err());
    assert!(store.recent_history(1).unwrap().is_empty());
    assert_eq!(reopened.get::<String>("requests", "request").unwrap().as_deref(), Some("before-close"));
    let accepted = reopened.seal("requests", "request", &"resumed").unwrap();
    store.commit_request_book(std::slice::from_ref(&accepted), Some(&history)).unwrap();
    assert_eq!(reopened.get::<String>("requests", "request").unwrap().as_deref(), Some("resumed"));
    assert_eq!(store.recent_history(1).unwrap()[0].status, "approved");
    reopened.close().unwrap();
    assert!(store.commit_request_book(&[accepted], None).is_err());
}
