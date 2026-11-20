//! Multiple authenticated callers of a cold generated GitHub grant.
use super::*;
use asm_proto::ErrorCode;
use reqwest::Method;

fn cold_pair(f: &Fixture) -> [String; 2] {
    std::array::from_fn(|_| {
        let state = f.request(f.body("GH_TOKEN")).unwrap();
        assert_eq!(state.status, RequestStatus::Pending);
        state.request_id
    })
}

#[test]
fn concurrent_posts_deliver_once_per_caller() {
    let f = Fixture::new();
    let clients = [wire_client(&f), wire_client(&f)];
    let body = f.body("GITHUB_TOKEN");
    let start = std::sync::Barrier::new(2);
    let submit = |i: usize| {
        start.wait();
        let (code, json) = clients[i](Method::POST, "requests", Some(&body));
        assert_eq!(code, 202);
        let state: RequestState = serde_json::from_value(json).unwrap();
        assert_eq!(state.status, RequestStatus::Pending);
        state.request_id
    };
    let ids = std::thread::scope(|s| {
        let a = s.spawn(|| submit(0));
        let b = submit(1);
        [a.join().unwrap(), b]
    });
    assert_ne!(ids[0], ids[1]);
    let snapshot = f.core.snapshot();
    assert_eq!(snapshot.pending.len(), 1);
    assert_eq!(f.issued(), 0);
    for (api, id) in clients.iter().zip(&ids) {
        let (code, json) = api(Method::GET, &format!("requests/{id}"), None);
        assert_eq!(code, 200);
        let state: RequestState = serde_json::from_value(json).unwrap();
        assert_eq!(state.request_id, *id);
        assert_eq!(state.status, RequestStatus::Pending);
    }
    f.approve(&snapshot.pending[0].id, "app-a", LeaseMode::Raw, 43_200).unwrap();
    let results = [0_usize, 1].map(|i| {
        let route = format!("requests/{}?wait=1", ids[i]);
        let (code, json) = clients[i](Method::GET, &route, None);
        assert_eq!(code, 200);
        let state: RequestState = serde_json::from_value(json).unwrap();
        assert_eq!(state.request_id, ids[i]);
        assert_eq!(state.status, RequestStatus::Approved);
        let result = get(state);
        assert_eq!(result.mode, LeaseMode::Raw);
        assert_eq!(result.credential_version, Some(1));
        assert_eq!(result.files.len(), 1);
        assert!(!result.files[0].content.is_empty());
        // A second poll must not consume the other caller's delivery, even before it has polled.
        assert_eq!(clients[i](Method::GET, &route, None).0, 503);
        result
    });
    assert_eq!(results[0].lease_id, results[1].lease_id);
    assert!(results[0].files == results[1].files);
    assert_eq!(f.core.store.list_leases().unwrap().len(), 1);
    assert_eq!(f.core.store.recent_history(2).unwrap().len(), 1);
    assert_eq!(f.issued(), 1);
}

#[test]
fn restart_preserves_pending_ids_and_individual_consumption() {
    let mut f = Fixture::new();
    let [first, second] = cold_pair(&f);
    let expires = f.core.request_state(&f.host.id, &first).unwrap().expires_at;
    f.restart();
    for id in [&first, &second] {
        let state = f.core.request_state(&f.host.id, id).unwrap();
        assert_eq!(state.request_id, *id);
        assert_eq!(state.expires_at, expires);
        assert_eq!(state.status, RequestStatus::Pending);
    }
    f.approve(&first, "app-a", LeaseMode::Raw, 43_200).unwrap();
    let old_proof = sha256(f.host.id.as_bytes());
    let a = get(f.core.request_state_with_proof(&f.host.id, &first, Some(&old_proof)).unwrap());
    f.restart();
    let new_proof = [23; 32];
    assert!(f.core.store.rotate_host_token(&f.host, &old_proof, &new_proof).unwrap());
    let poll = |id, proof| f.core.request_state_with_proof(&f.host.id, id, Some(proof));
    assert!(matches!(poll(&first, &new_proof), Err(e) if e.code == ErrorCode::VaultUnavailable));
    assert!(matches!(poll(&second, &old_proof), Err(e) if e.code == ErrorCode::Unauthorized));
    let b = get(poll(&second, &new_proof).unwrap());
    assert_eq!(a.lease_id, b.lease_id);
    assert!(!a.files.is_empty() && a.files == b.files);
    assert_eq!(f.issued(), 1);
}

#[test]
fn shared_denial_returns_no_result_to_either_caller() {
    let f = Fixture::new();
    let ids = cold_pair(&f);
    f.core.resolve_request(&ids[0], ffi::Decision::Deny { reason: "declined".into() }).unwrap();
    for id in ids {
        let state = f.core.request_state(&f.host.id, &id).unwrap();
        assert_eq!(state.request_id, id);
        assert_eq!(state.status, RequestStatus::Denied);
        assert_eq!(state.deny_reason.as_deref(), Some("declined"));
        assert!(state.result.is_none());
    }
    assert_eq!(f.issued(), 0);
    assert!(f.core.store.list_leases().unwrap().is_empty());
}

#[test]
fn remaining_delivery_requires_current_host_lease_and_credential() {
    enum End { RevokeLease, RevokeHost, ExpireToken, ExpireLease }
    for end in [End::RevokeLease, End::RevokeHost, End::ExpireToken, End::ExpireLease] {
        let f = Fixture::new();
        f.provider.state.ttl.store(600, Ordering::SeqCst);
        let [first, joined] = cold_pair(&f);
        f.approve(&first, "app-a", LeaseMode::Raw, if matches!(end, End::ExpireLease) { 60 } else { 3600 }).unwrap();
        let issued = get(f.core.request_state(&f.host.id, &first).unwrap());
        match end {
            End::RevokeLease => f.core.revoke_lease(&issued.lease_id).unwrap(),
            End::RevokeHost => f.core.revoke_host(&f.host.id).unwrap(),
            End::ExpireToken => f.at(600),
            End::ExpireLease => f.at(60),
        }
        let proof = sha256(f.host.id.as_bytes());
        let expected = if matches!(end, End::RevokeHost) { ErrorCode::Unauthorized } else { ErrorCode::VaultUnavailable };
        assert!(matches!(f.core.request_state_with_proof(&f.host.id, &joined, Some(&proof)), Err(e) if e.code == expected));
        assert_eq!(f.issued(), 1);
    }
}

#[test]
fn cancelling_after_approval_discards_only_one_delivery() {
    let f = Fixture::new();
    let [first, joined] = cold_pair(&f);
    f.approve(&first, "app-a", LeaseMode::Raw, 43_200).unwrap();
    let cancelled = f.core.cancel_request(&f.host.id, &joined).unwrap();
    assert_eq!(cancelled.request_id, joined);
    assert!(cancelled.result.is_none());
    assert!(f.core.request_state(&f.host.id, &joined).is_err());
    assert_eq!(get(f.core.request_state(&f.host.id, &first).unwrap()).credential_version, Some(1));
    assert_eq!(f.issued(), 1);
}

#[test]
fn distinct_repo_permission_and_pinned_source_need_separate_decisions() {
    let f = Fixture::new();
    let mut ceiling = Fixture::grant();
    ceiling.installation_id = 8;
    ceiling.repositories.push(GithubRepository { id: 2, full_name: "acme/repo2".into() });
    ceiling.permissions.insert("contents".into(), GithubPermission::Write);
    f.install_with_ceilings("app-b", "review-bot", 2, vec![ceiling]);
    let [first, joined] = cold_pair(&f);
    let others = [f.github_body(false, &["acme/repo2"], GithubPermission::Read),
        f.github_body(false, &["acme/repo1"], GithubPermission::Write), f.body("review-bot/GH_TOKEN")];
    let other_ids = others.map(|body| f.request(body).unwrap().request_id);
    assert_eq!(f.core.snapshot().pending.len(), 4);
    f.approve(&first, "app-a", LeaseMode::Raw, 43_200).unwrap();
    let result = get(f.core.request_state(&f.host.id, &joined).unwrap());
    assert_eq!(result.generation.unwrap().grant, GenerationGrant::GithubApp(Fixture::grant()));
    for id in other_ids {
        let state = f.core.request_state(&f.host.id, &id).unwrap();
        assert_eq!(state.status, RequestStatus::Pending);
        assert!(state.result.is_none());
    }
    assert_eq!(f.issued(), 1);
}
