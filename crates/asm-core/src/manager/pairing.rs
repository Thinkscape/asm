//! Host pairing: interactive commit/reveal (popup with a verification code) and unattended
//! pairing codes (no popup).

use std::net::IpAddr;

use asm_proto::crypto::{ct_eq, hex_decode_array, new_token, new_uuid_v4, sha256};
use asm_proto::pairing::{
    NONCE_LEN, UnattendedCode, format_pairing_code, new_nonce, pairing_code, verify_commit,
};
use asm_proto::rules::validate_agent_text;
use asm_proto::time::fmt_unix;
use asm_proto::wire::{HostInfo, PairRequest, PairResponse, RevealRequest};
use serde_json::json;

use super::activity::{self, Category, Event};
use super::netinfo::network_allows;
use super::requests::{Book, Detail, Fail, Pending, REVEAL_SECS};
use super::{Core, TOPIC_HOSTS, TOPIC_REQUESTS, lock, now};
use crate::error::{CoreError, Result};
use crate::store::{CodeUse, HostRecord, Store};

/// At most this many open pairing attempts per remote address, and in total.
const MAX_PER_ADDRESS: usize = 1;
const MAX_TOTAL: usize = 5;

/// Longest friendly host name, in Unicode scalar values.
const MAX_HOST_NAME: usize = 64;

/// A host's friendly name as the operator typed it: trimmed, empty = `hostname`, at most
/// 64 characters, no control or bidi characters (`invalid`).
pub(crate) fn host_name(raw: &str, hostname: &str) -> Result<String> {
    let name = raw.trim();
    if name.is_empty() {
        return Ok(hostname.to_string());
    }
    validate_agent_text("name", name)?;
    if name.chars().count() > MAX_HOST_NAME {
        return Err(CoreError::invalid(format!(
            "name must be at most {MAX_HOST_NAME} characters"
        )));
    }
    Ok(name.to_string())
}

#[derive(Debug, Clone)]
pub(crate) enum PairState {
    AwaitingReveal,
    Pending,
    Denied(Option<String>),
    Expired,
    Approved { host_id: String, token: String },
}

#[derive(Debug, Clone)]
pub(crate) struct PairAttempt {
    pub id: String,
    poll_hash: [u8; 32],
    commit: [u8; 32],
    server_nonce: [u8; NONCE_LEN],
    pub info: HostInfo,
    pub ip: String,
    pub expires: i64,
    pub state: PairState,
    /// When the attempt reached a terminal state (for pruning).
    pub ended: Option<i64>,
}

impl PairAttempt {
    fn open(&self) -> bool {
        matches!(self.state, PairState::AwaitingReveal | PairState::Pending)
    }
}

fn check_poll(a: &PairAttempt, poll_token: &str) -> Result<()> {
    if ct_eq(&sha256(poll_token.as_bytes()), &a.poll_hash) {
        Ok(())
    } else {
        Err(CoreError::not_found("no such pairing request"))
    }
}

/// `POST /pair` without a code: register the client's commitment and answer a server nonce.
pub(crate) fn start_attempt(
    book: &mut Book,
    commit_hex: &str,
    info: HostInfo,
    ip: &str,
    t: i64,
) -> Result<PairResponse> {
    let commit: [u8; 32] = hex_decode_array(commit_hex)
        .ok_or_else(|| CoreError::invalid("client_commit must be 64 hex digits"))?;
    let open: Vec<&PairAttempt> = book.pairs.values().filter(|a| a.open()).collect();
    if open.iter().filter(|a| a.ip == ip).count() >= MAX_PER_ADDRESS {
        return Err(CoreError::rate_limited(
            "a pairing request from this address is already pending",
        ));
    }
    if open.len() >= MAX_TOTAL {
        return Err(CoreError::rate_limited(
            "too many pairing requests are pending",
        ));
    }
    let id = new_uuid_v4();
    let poll_token = new_token();
    let server_nonce = new_nonce();
    book.pairs.insert(
        id.clone(),
        PairAttempt {
            id: id.clone(),
            poll_hash: sha256(poll_token.as_bytes()),
            commit,
            server_nonce,
            info,
            ip: ip.to_string(),
            expires: t + REVEAL_SECS,
            state: PairState::AwaitingReveal,
            ended: None,
        },
    );
    Ok(PairResponse::AwaitingReveal {
        pair_id: id,
        poll_token,
        server_nonce: asm_proto::crypto::hex_encode(&server_nonce),
    })
}

/// `POST /pair/{id}/reveal`: check the commitment, derive the code and queue the popup.
pub(crate) fn reveal_attempt(
    book: &mut Book,
    cert_sha256: &[u8; 32],
    pair_id: &str,
    req: &RevealRequest,
    t: i64,
    lifetime: i64,
) -> Result<PairResponse> {
    let a = book
        .pairs
        .get(pair_id)
        .ok_or_else(|| CoreError::not_found("no such pairing request"))?;
    check_poll(a, &req.poll_token)?;
    match a.state {
        PairState::AwaitingReveal => {}
        PairState::Pending => {
            return Ok(PairResponse::Pending {
                deny_reason: None,
                expires_at: Some(fmt_unix(a.expires)),
            });
        }
        _ => {
            return Err(CoreError::invalid(
                "this pairing request is no longer waiting for a reveal",
            ));
        }
    }
    let nonce: [u8; NONCE_LEN] = hex_decode_array(&req.client_nonce)
        .ok_or_else(|| CoreError::invalid("client_nonce must be 32 hex digits"))?;
    if !verify_commit(&a.commit, &nonce) {
        book.pairs.remove(pair_id);
        return Err(CoreError::invalid(
            "client_nonce does not match the commitment",
        ));
    }
    let code = format_pairing_code(pairing_code(cert_sha256, &nonce, &a.server_nonce));
    let a = book.pairs.get_mut(pair_id).expect("checked above");
    a.state = PairState::Pending;
    a.expires = t + lifetime;
    let pending = Pending {
        id: a.id.clone(),
        created: t,
        expires: t + lifetime,
        host_id: None,
        host_label: a.info.hostname.clone(),
        host_info: Some(a.info.clone()),
        agent: String::new(),
        resolving: false,
        error: None,
        detail: Detail::Pair {
            info: a.info.clone(),
            address: a.ip.clone(),
            code,
        },
    };
    book.pending.push(pending);
    Ok(PairResponse::Pending {
        deny_reason: None,
        expires_at: Some(fmt_unix(t + lifetime)),
    })
}

/// `GET /pair/{id}`: the attempt's state; `approved` (with the token) is returned once.
pub(crate) fn poll_attempt(
    book: &mut Book,
    pair_id: &str,
    poll_token: &str,
) -> Result<PairResponse> {
    let a = book
        .pairs
        .get(pair_id)
        .ok_or_else(|| CoreError::not_found("no such pairing request"))?;
    check_poll(a, poll_token)?;
    Ok(match &a.state {
        PairState::AwaitingReveal | PairState::Pending => PairResponse::Pending {
            deny_reason: None,
            expires_at: Some(fmt_unix(a.expires)),
        },
        PairState::Denied(r) => PairResponse::Denied {
            deny_reason: r.clone(),
        },
        PairState::Expired => PairResponse::Expired { deny_reason: None },
        PairState::Approved { host_id, token } => {
            let r = PairResponse::Approved {
                host_id: host_id.clone(),
                token: token.clone(),
            };
            book.pairs.remove(pair_id);
            r
        }
    })
}

/// Outcome of [`pair_with_code`] for a code that is otherwise valid.
#[derive(Debug)]
pub(crate) enum CodePairing {
    Paired {
        host_id: String,
        token: String,
        label: String,
    },
    /// The code is limited to `networks` and the peer address is outside all of them;
    /// nothing changed (the code keeps its uses).
    WrongNetwork {
        label: String,
        networks: Vec<String>,
    },
}

/// Unattended pairing: check the code against the certificate and the store (atomically
/// checking the peer address `ip`, as observed on the TCP connection, against the code's
/// networks and counting one use) and create the host. A bad, expired, used-up or revoked
/// code is `unauthorized`.
pub(crate) fn pair_with_code(
    store: &Store,
    cert_sha256: &[u8; 32],
    code: &str,
    info: HostInfo,
    ip: &str,
    t: i64,
) -> Result<CodePairing> {
    let rejected = || CoreError::unauthorized("pairing code rejected");
    let code = UnattendedCode::parse(code).map_err(|_| rejected())?;
    if !code.matches_cert(cert_sha256) {
        return Err(rejected());
    }
    let peer = ip.parse::<IpAddr>().ok().map(|a| a.to_canonical());
    let token = new_token();
    let host = HostRecord {
        id: new_uuid_v4(),
        name: info.hostname.clone(),
        info,
        address: ip.to_string(),
        paired_at: t,
        last_seen: Some(t),
        revoked_at: None,
    };
    match store.consume_pairing_code(
        &code.secret_sha256(),
        t,
        &host,
        &sha256(token.as_bytes()),
        |networks| network_allows(networks, peer),
    )? {
        CodeUse::Paired { label } => Ok(CodePairing::Paired {
            host_id: host.id,
            token,
            label,
        }),
        CodeUse::WrongNetwork { label, networks } => {
            Ok(CodePairing::WrongNetwork { label, networks })
        }
        CodeUse::Rejected => Err(rejected()),
    }
}

impl Core {
    /// `POST /pair`.
    pub fn pair_start(&self, req: PairRequest, ip: &str) -> Result<PairResponse> {
        req.host_info.validate()?;
        let t = now();
        if let Some(code) = req.pairing_code.as_deref().filter(|c| !c.trim().is_empty()) {
            let hostname = req.host_info.hostname.clone();
            let info = serde_json::to_value(&req.host_info).unwrap_or_default();
            match pair_with_code(&self.store, &self.cert.sha256, code, req.host_info, ip, t)? {
                CodePairing::Paired {
                    host_id,
                    token,
                    label,
                } => {
                    self.log(
                        Event::new(
                            Category::Pairing,
                            "paired_with_code",
                            format!("{hostname} paired with pairing code \"{label}\""),
                        )
                        .host(Some(&host_id))
                        .detail(json!({ "code_label": label, "address": ip, "host_info": info })),
                    );
                    self.notify(TOPIC_HOSTS);
                    return Ok(PairResponse::Approved { host_id, token });
                }
                CodePairing::WrongNetwork { label, networks } => {
                    self.log(
                        Event::new(
                            Category::Pairing,
                            "code_rejected_network",
                            format!(
                                "{hostname} at {ip} presented pairing code \"{label}\" from outside its allowed networks"
                            ),
                        )
                        .detail(json!({
                            "code_label": label,
                            "address": ip,
                            "allowed_networks": networks,
                            "host_info": info,
                        })),
                    );
                    return Err(CoreError::unauthorized(
                        "pairing code not valid from this address",
                    ));
                }
            }
        }
        self.expire_requests(t);
        let r = start_attempt(
            &mut lock(&self.book),
            &req.client_commit,
            req.host_info,
            ip,
            t,
        )?;
        self.bump();
        Ok(r)
    }

    /// `POST /pair/{id}/reveal`.
    pub fn pair_reveal(&self, pair_id: &str, req: RevealRequest) -> Result<PairResponse> {
        let t = now();
        self.expire_requests(t);
        let lifetime = self.settings().request_lifetime_secs.max(1) as i64;
        let (r, popup) = {
            let mut b = lock(&self.book);
            let awaiting = b
                .pairs
                .get(pair_id)
                .is_some_and(|a| matches!(a.state, PairState::AwaitingReveal));
            let r = reveal_attempt(&mut b, &self.cert.sha256, pair_id, &req, t, lifetime)?;
            let popup = awaiting
                .then(|| b.pending.iter().find(|p| p.id == pair_id).cloned())
                .flatten();
            (r, popup)
        };
        if let Some(p) = popup {
            self.log(activity::requested(&p));
        }
        self.bump();
        self.notify(TOPIC_REQUESTS);
        Ok(r)
    }

    /// `GET /pair/{id}` (one check; the API layer long-polls).
    pub fn pair_poll(&self, pair_id: &str, poll_token: &str) -> Result<PairResponse> {
        self.expire_requests(now());
        poll_attempt(&mut lock(&self.book), pair_id, poll_token)
    }

    /// Operator approved a pairing popup: create the host (named `name`, see [`host_name`])
    /// and hand its token to the poller.
    pub(crate) fn approve_pair(&self, p: &Pending, name: &str) -> std::result::Result<(), Fail> {
        let Detail::Pair { info, address, .. } = &p.detail else {
            return Err(Fail::Keep(CoreError::invalid("not a pairing request")));
        };
        let name = host_name(name, &info.hostname).map_err(Fail::Keep)?;
        let t = now();
        let token = new_token();
        let host = HostRecord {
            id: new_uuid_v4(),
            info: info.clone(),
            name,
            address: address.clone(),
            paired_at: t,
            last_seen: Some(t),
            revoked_at: None,
        };
        self.store.insert_host(&host, &sha256(token.as_bytes()))?;
        let mut b = lock(&self.book);
        // History of this request names the new host.
        if let Some(q) = b.pending.iter_mut().find(|q| q.id == p.id) {
            q.host_id = Some(host.id.clone());
            q.host_label = host.name.clone();
        }
        if let Some(a) = b.pairs.get_mut(&p.id) {
            a.state = PairState::Approved {
                host_id: host.id.clone(),
                token,
            };
        }
        drop(b);
        self.notify(TOPIC_HOSTS);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::PairingCodeRecord;
    use asm_proto::crypto::hex_encode;
    use asm_proto::pairing::client_commit;

    const CERT: [u8; 32] = [0x42; 32];

    fn info(name: &str) -> HostInfo {
        HostInfo {
            hostname: name.into(),
            ..Default::default()
        }
    }

    #[test]
    fn friendly_host_names() {
        assert_eq!(host_name("  Build box  ", "nuk1").unwrap(), "Build box");
        assert_eq!(host_name("   ", "nuk1").unwrap(), "nuk1");
        assert_eq!(host_name(&"é".repeat(64), "h").unwrap().chars().count(), 64);
        assert!(host_name(&"é".repeat(65), "h").is_err());
        assert!(host_name("box\u{7}", "h").is_err());
        assert!(host_name("box\u{202E}", "h").is_err());
        assert_eq!(
            host_name("a\u{202E}", "h").unwrap_err().code,
            asm_proto::ErrorCode::Invalid
        );
    }

    fn awaiting(r: PairResponse) -> (String, String, [u8; NONCE_LEN]) {
        match r {
            PairResponse::AwaitingReveal {
                pair_id,
                poll_token,
                server_nonce,
            } => (
                pair_id,
                poll_token,
                hex_decode_array(&server_nonce).unwrap(),
            ),
            other => panic!("unexpected {other:?}"),
        }
    }

    fn popup_code(book: &Book, id: &str) -> String {
        match &book.pending.iter().find(|p| p.id == id).unwrap().detail {
            Detail::Pair { code, .. } => code.clone(),
            _ => unreachable!(),
        }
    }

    #[test]
    fn both_sides_derive_the_same_code() {
        let mut book = Book::default();
        let client_nonce = new_nonce();
        let commit = hex_encode(&client_commit(&client_nonce));
        let (id, poll, server_nonce) =
            awaiting(start_attempt(&mut book, &commit, info("box"), "10.0.0.2", 100).unwrap());
        // Before the reveal there is no popup.
        assert!(book.pending.is_empty());
        let reveal = RevealRequest {
            poll_token: poll.clone(),
            client_nonce: hex_encode(&client_nonce),
        };
        reveal_attempt(&mut book, &CERT, &id, &reveal, 101, 600).unwrap();
        let cli_code = format_pairing_code(pairing_code(&CERT, &client_nonce, &server_nonce));
        assert_eq!(popup_code(&book, &id), cli_code);
        assert_eq!(cli_code.len(), 7);
        assert!(matches!(
            poll_attempt(&mut book, &id, &poll).unwrap(),
            PairResponse::Pending { .. }
        ));
        assert!(poll_attempt(&mut book, &id, "wrong").is_err());
    }

    #[test]
    fn relay_substituting_its_nonce_cannot_match_codes() {
        let mut book = Book::default();
        // The client commits to its nonce and sends the commit to a relay.
        let client_nonce = [1u8; NONCE_LEN];
        let _client_commit = client_commit(&client_nonce);
        // The relay must commit toward the manager before it learns the server nonce.
        let relay_nonce = [2u8; NONCE_LEN];
        let relay_commit = hex_encode(&client_commit(&relay_nonce));
        let (id, poll, server_nonce) = awaiting(
            start_attempt(&mut book, &relay_commit, info("relay"), "10.0.0.9", 100).unwrap(),
        );
        // Revealing the client's nonce under the relay's commitment fails.
        let bad = RevealRequest {
            poll_token: poll.clone(),
            client_nonce: hex_encode(&client_nonce),
        };
        let err = reveal_attempt(&mut book, &CERT, &id, &bad, 101, 600).unwrap_err();
        assert_eq!(err.code, asm_proto::ErrorCode::Invalid);
        assert!(book.pending.is_empty());
        assert!(
            book.pairs.is_empty(),
            "failed commit check drops the attempt"
        );

        // Revealing its own nonce passes the commit check, but the codes differ.
        let (id, poll, server_nonce2) = awaiting(
            start_attempt(&mut book, &relay_commit, info("relay"), "10.0.0.9", 102).unwrap(),
        );
        let ok = RevealRequest {
            poll_token: poll,
            client_nonce: hex_encode(&relay_nonce),
        };
        reveal_attempt(&mut book, &CERT, &id, &ok, 103, 600).unwrap();
        let manager_code = popup_code(&book, &id);
        for ns in [server_nonce, server_nonce2] {
            let client_code = format_pairing_code(pairing_code(&CERT, &client_nonce, &ns));
            assert_ne!(manager_code, client_code);
        }
    }

    #[test]
    fn pairing_rate_limits() {
        let mut book = Book::default();
        let commit = hex_encode(&[0u8; 32]);
        start_attempt(&mut book, &commit, info("a"), "10.0.0.1", 100).unwrap();
        let e = start_attempt(&mut book, &commit, info("a"), "10.0.0.1", 100).unwrap_err();
        assert_eq!(e.code, asm_proto::ErrorCode::RateLimited);
        for i in 2..=5 {
            start_attempt(&mut book, &commit, info("x"), &format!("10.0.0.{i}"), 100).unwrap();
        }
        let e = start_attempt(&mut book, &commit, info("x"), "10.0.0.6", 100).unwrap_err();
        assert_eq!(e.code, asm_proto::ErrorCode::RateLimited);
        assert!(start_attempt(&mut book, "zz", info("x"), "10.0.0.7", 100).is_err());
    }

    #[test]
    fn approved_token_is_returned_once() {
        let mut book = Book::default();
        let n = new_nonce();
        let (id, poll, _) = awaiting(
            start_attempt(
                &mut book,
                &hex_encode(&client_commit(&n)),
                info("b"),
                "10.0.0.3",
                1,
            )
            .unwrap(),
        );
        book.pairs.get_mut(&id).unwrap().state = PairState::Approved {
            host_id: "h".into(),
            token: "t".into(),
        };
        assert!(matches!(
            poll_attempt(&mut book, &id, &poll).unwrap(),
            PairResponse::Approved { .. }
        ));
        assert_eq!(
            poll_attempt(&mut book, &id, &poll).unwrap_err().code,
            asm_proto::ErrorCode::NotFound
        );
    }

    #[test]
    fn unattended_codes() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("asm.db")).unwrap();
        let code = UnattendedCode::generate(&CERT);
        let rec = |id: &str, expires_at, max_uses, networks: &[&str]| PairingCodeRecord {
            id: id.into(),
            label: "ci".into(),
            created_at: 0,
            expires_at,
            max_uses,
            uses: 0,
            revoked_at: None,
            networks: networks.iter().map(|n| n.to_string()).collect(),
        };
        store
            .insert_pairing_code(&rec("c1", Some(1000), Some(1), &[]), &code.secret_sha256())
            .unwrap();
        let s = code.to_string();
        let unauthorized = |r: Result<CodePairing>| {
            assert_eq!(r.unwrap_err().code, asm_proto::ErrorCode::Unauthorized)
        };

        // Wrong certificate fingerprint.
        unauthorized(pair_with_code(&store, &[0x43; 32], &s, info("a"), "ip", 10));
        // Garbage.
        unauthorized(pair_with_code(
            &store,
            &CERT,
            "asm-nope",
            info("a"),
            "ip",
            10,
        ));
        // Expired.
        unauthorized(pair_with_code(&store, &CERT, &s, info("a"), "ip", 1000));
        // Valid once (no networks: any address, even an unparseable one), then used up.
        let CodePairing::Paired {
            host_id,
            token,
            label,
        } = pair_with_code(&store, &CERT, &s, info("a"), "ip", 10).unwrap()
        else {
            panic!("not paired")
        };
        assert_eq!(label, "ci");
        let h = store
            .host_by_token(&sha256(token.as_bytes()))
            .unwrap()
            .unwrap();
        assert_eq!(h.id, host_id);
        unauthorized(pair_with_code(&store, &CERT, &s, info("b"), "ip", 11));
        // Unknown secret with the right fingerprint.
        let other = UnattendedCode::generate(&CERT).to_string();
        unauthorized(pair_with_code(&store, &CERT, &other, info("c"), "ip", 11));

        // Limited to networks: the observed peer address decides; a mismatch keeps the use.
        let limited = UnattendedCode::generate(&CERT);
        store
            .insert_pairing_code(
                &rec("c2", None, Some(1), &["10.0.0.0/8", "fd00::/8"]),
                &limited.secret_sha256(),
            )
            .unwrap();
        let l = limited.to_string();
        for peer in ["192.0.2.1", "::ffff:192.0.2.1", "fe80::1", "ip"] {
            match pair_with_code(&store, &CERT, &l, info("d"), peer, 12).unwrap() {
                CodePairing::WrongNetwork { label, networks } => {
                    assert_eq!(label, "ci");
                    assert_eq!(networks, ["10.0.0.0/8", "fd00::/8"]);
                }
                other => panic!("{peer}: {other:?}"),
            }
        }
        let uses = |id: &str| {
            store
                .list_pairing_codes()
                .unwrap()
                .into_iter()
                .find(|c| c.id == id)
                .unwrap()
                .uses
        };
        assert_eq!(uses("c2"), 0, "a network mismatch does not use up the code");
        assert!(matches!(
            pair_with_code(&store, &CERT, &l, info("d"), "::ffff:10.1.2.3", 12).unwrap(),
            CodePairing::Paired { .. }
        ));
        assert_eq!(uses("c2"), 1);

        let v6 = UnattendedCode::generate(&CERT);
        store
            .insert_pairing_code(&rec("c3", None, None, &["fd00::/8"]), &v6.secret_sha256())
            .unwrap();
        assert!(matches!(
            pair_with_code(&store, &CERT, &v6.to_string(), info("e"), "fd12::7", 12).unwrap(),
            CodePairing::Paired { .. }
        ));
    }
}
