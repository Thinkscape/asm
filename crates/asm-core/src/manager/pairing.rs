//! Host pairing: interactive commit/reveal (popup with a verification code) and unattended
//! pairing codes (no popup).

use std::net::IpAddr;

use asm_proto::crypto::{ct_eq, hex_decode_array, new_token, new_uuid_v4, sha256};
use asm_proto::pairing::{
    NONCE_LEN, UnattendedCode, format_pairing_code, new_nonce, pairing_code, verify_commit,
};
use asm_proto::rules::validate_agent_text;
use asm_proto::time::fmt_unix;
use asm_proto::wire::{HostInfo, PairProof, PairRequest, PairResponse, RequestStatus, RevealRequest};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::activity::{self, Category, Event};
use super::netinfo::network_allows;
use super::requests::{Book, Detail, Fail, Pending, REVEAL_SECS};
use super::{Core, TOPIC_HOSTS, TOPIC_REQUESTS, lock, now};
use crate::error::{CoreError, Result};
use crate::store::{CodeUse, HostRecord, Store};

/// At most one open attempt per observed address, and this many overall.
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

#[derive(Clone, Serialize, Deserialize)]
pub(crate) enum PairState {
    AwaitingReveal,
    Pending,
    Denied(Option<String>),
    Expired,
    Approved { host_id: String, token: String },
}

/// The existing host a pairing request relates to.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Repair {
    pub host_id: String,
    /// The host's friendly name.
    pub host_name: String,
    pub paired_at: i64,
    /// `Some(token hash)`: the CLI proved it holds this host's current token
    /// (`same_install`); `None`: only the forgeable machine hint matches (`same_machine`).
    pub proof: Option<[u8; 32]>,
}

impl Repair {
    pub(crate) fn kind(&self) -> &'static str {
        if self.proof.is_some() {
            "same_install"
        } else {
            "same_machine"
        }
    }

    fn new(h: &HostRecord, proof: Option<[u8; 32]>) -> Self {
        Repair {
            host_id: h.id.clone(),
            host_name: h.label().to_string(),
            paired_at: h.paired_at,
            proof,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
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
    /// The machine hint the CLI claimed.
    pub machine_hint: Option<String>,
    /// The existing host this attempt relates to (shown in the popup).
    pub repair: Option<Repair>,
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
fn start_attempt(
    book: &Book,
    commit_hex: &str,
    info: HostInfo,
    ip: &str,
    t: i64,
) -> Result<(PairAttempt, PairResponse)> {
    let commit: [u8; 32] = hex_decode_array(commit_hex)
        .ok_or_else(|| CoreError::invalid("client_commit must be 64 hex digits"))?;
    if book.pairs.values().any(|a| a.open() && a.ip == ip) {
        return Err(CoreError::rate_limited(
            "a pairing request from this address is already pending",
        ));
    }
    if book.pairs.values().filter(|a| a.open()).count() >= MAX_TOTAL {
        return Err(CoreError::rate_limited(
            "too many pairing requests are pending",
        ));
    }
    let id = new_uuid_v4();
    let poll_token = new_token();
    let server_nonce = new_nonce();
    let attempt = PairAttempt {
        id: id.clone(),
        poll_hash: sha256(poll_token.as_bytes()),
        commit,
        server_nonce,
        info,
        ip: ip.to_string(),
        expires: t + REVEAL_SECS,
        state: PairState::AwaitingReveal,
        ended: None,
        machine_hint: None,
        repair: None,
    };
    Ok((attempt, PairResponse::AwaitingReveal {
        pair_id: id,
        poll_token,
        server_nonce: asm_proto::crypto::hex_encode(&server_nonce),
    }))
}

enum Reveal {
    AlreadyRevealed,
    CommitmentMismatch,
    Revealed(Pending),
}

/// `POST /pair/{id}/reveal`: check the commitment, derive the code and queue the popup.
fn reveal_attempt(
    a: &PairAttempt,
    cert_sha256: &[u8; 32],
    req: &RevealRequest,
    t: i64,
    lifetime: i64,
) -> Result<Reveal> {
    check_poll(a, &req.poll_token)?;
    match a.state {
        PairState::AwaitingReveal => {}
        PairState::Pending => return Ok(Reveal::AlreadyRevealed),
        _ => {
            return Err(CoreError::invalid(
                "this pairing request is no longer waiting for a reveal",
            ));
        }
    }
    let nonce: [u8; NONCE_LEN] = hex_decode_array(&req.client_nonce)
        .ok_or_else(|| CoreError::invalid("client_nonce must be 32 hex digits"))?;
    if !verify_commit(&a.commit, &nonce) {
        return Ok(Reveal::CommitmentMismatch);
    }
    let code = format_pairing_code(pairing_code(cert_sha256, &nonce, &a.server_nonce));
    Ok(Reveal::Revealed(Pending {
        id: a.id.clone(),
        created: t,
        expires: t + lifetime,
        host_id: None,
        host_label: a.info.hostname.clone(),
        host_info: Some(a.info.clone()),
        agent: String::new(),
        address: a.ip.clone(),
        resolving: false,
        error: None,
        detail: Detail::Pair {
            info: a.info.clone(),
            address: a.ip.clone(),
            code,
            machine_hint: a.machine_hint.clone(),
            repair: a.repair.clone(),
        },
    }))
}

/// `GET /pair/{id}`: the attempt's state; `approved` (with the token) is returned once.
fn poll_attempt(
    book: &mut Book,
    pair_id: &str,
    poll_token: &str,
    before_delivery: impl FnOnce(&str, &str) -> Result<()>,
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
            before_delivery(host_id, token)?;
            let attempt = book.pairs.remove(pair_id).expect("same locked attempt");
            let PairState::Approved { host_id, token } = attempt.state else { unreachable!() };
            PairResponse::Approved { host_id, token }
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
        /// The proven existing host got the new token (no new host record).
        rotated: bool,
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
/// networks and counting one use) and create the host, or with `proven` (an existing host
/// id and the hash of its current token, as proven by the caller) rotate that host's token.
/// A proof that no longer holds when the code is consumed falls back to a new host. A bad,
/// expired, used-up or revoked code is `unauthorized`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn pair_with_code(
    store: &Store,
    cert_sha256: &[u8; 32],
    code: &str,
    info: HostInfo,
    machine_hint: Option<String>,
    proven: Option<(&str, &[u8; 32])>,
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
    let token_hash = sha256(token.as_bytes());
    let host = HostRecord {
        id: new_uuid_v4(),
        name: info.hostname.clone(),
        info,
        address: ip.to_string(),
        paired_at: t,
        last_seen: Some(t),
        revoked_at: None,
        machine_hint,
    };
    let consume = |h: &HostRecord, rotate_from: Option<&[u8; 32]>| {
        store.consume_pairing_code(
            &code.secret_sha256(),
            t,
            h,
            &token_hash,
            rotate_from,
            |networks| network_allows(networks, peer),
        )
    };
    let (host_id, used, rotated) = match proven {
        Some((id, old_hash)) => {
            let existing = HostRecord {
                id: id.to_string(),
                ..host.clone()
            };
            match consume(&existing, Some(old_hash))? {
                // The proof no longer holds: a normal new host.
                CodeUse::StaleProof => (host.id.clone(), consume(&host, None)?, false),
                used => (existing.id, used, true),
            }
        }
        None => (host.id.clone(), consume(&host, None)?, false),
    };
    match used {
        CodeUse::Paired { label } => Ok(CodePairing::Paired {
            host_id,
            token,
            label,
            rotated,
        }),
        CodeUse::WrongNetwork { label, networks } => {
            Ok(CodePairing::WrongNetwork { label, networks })
        }
        CodeUse::Rejected | CodeUse::StaleProof => Err(rejected()),
    }
}

impl Core {
    /// The active host proven by `previous` (its id and current token) and its token hash.
    fn proven_host(&self, previous: Option<&PairProof>) -> Result<Option<(HostRecord, [u8; 32])>> {
        let Some(p) = previous else { return Ok(None) };
        let hash = sha256(p.token.as_bytes());
        Ok(self
            .store
            .host_by_proof(&p.host_id, &hash)?
            .map(|h| (h, hash)))
    }

    /// `POST /pair`.
    pub fn pair_start(&self, req: PairRequest, ip: &str) -> Result<PairResponse> {
        req.validate()?;
        let t = now();
        // An invalid or revoked proof is ignored: the request is a normal new pairing.
        let proven = self.proven_host(req.previous.as_ref())?;
        let hint_matches = match (&proven, req.machine_hint.as_deref()) {
            (None, Some(hint)) => self.store.hosts_with_hint(hint)?,
            _ => Vec::new(),
        };
        if let Some(code) = req.pairing_code.as_deref().filter(|c| !c.trim().is_empty()) {
            let hostname = req.host_info.hostname.clone();
            let info = serde_json::to_value(&req.host_info).unwrap_or_default();
            let paired = {
                let _authority = lock(&self.authorization);
                pair_with_code(
                    &self.store, &self.cert.sha256, code, req.host_info, req.machine_hint.clone(),
                    proven.as_ref().map(|(h, hash)| (h.id.as_str(), hash)), ip, t,
                )?
            };
            match paired {
                CodePairing::Paired {
                    host_id,
                    token,
                    label,
                    rotated: true,
                } => {
                    let name = proven
                        .map(|(h, _)| h.label().to_string())
                        .unwrap_or_default();
                    self.log(
                        Event::new(
                            Category::Pairing,
                            "repaired_with_code",
                            format!(
                                "{name} paired again with pairing code \"{label}\"; its old token no longer works"
                            ),
                        )
                        .host(Some(&host_id))
                        .detail(json!({ "code_label": label, "address": ip, "host_info": info })),
                    );
                    self.notify(TOPIC_HOSTS);
                    return Ok(PairResponse::Approved { host_id, token });
                }
                CodePairing::Paired {
                    host_id,
                    token,
                    label,
                    rotated: false,
                } => {
                    let mut detail =
                        json!({ "code_label": label, "address": ip, "host_info": info });
                    if !hint_matches.is_empty() {
                        let names: Vec<&str> = hint_matches.iter().map(|h| h.label()).collect();
                        detail["warning"] = json!(format!(
                            "same machine hint as {}; not replaced (pairing codes never replace hosts)",
                            names.join(", ")
                        ));
                        detail["machine_hint_matches"] =
                            json!(hint_matches.iter().map(|h| &h.id).collect::<Vec<_>>());
                    }
                    self.log(
                        Event::new(
                            Category::Pairing,
                            "paired_with_code",
                            format!("{hostname} paired with pairing code \"{label}\""),
                        )
                        .host(Some(&host_id))
                        .detail(detail),
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
        let repair = match &proven {
            Some((h, hash)) => Some(Repair::new(h, Some(*hash))),
            None => hint_matches.first().map(|h| Repair::new(h, None)),
        };
        self.expire_requests(t)?;
        let r = {
            let mut book = lock(&self.book);
            let (mut attempt, response) = start_attempt(&book, &req.client_commit, req.host_info, ip, t)?;
            attempt.machine_hint = req.machine_hint;
            attempt.repair = repair;
            self.save_pair_locked(&mut book, attempt, None, None)?;
            response
        };
        self.bump();
        Ok(r)
    }

    /// `POST /pair/{id}/reveal`.
    pub fn pair_reveal(&self, pair_id: &str, req: RevealRequest) -> Result<PairResponse> {
        let t = now();
        self.expire_requests(t)?;
        let lifetime = self.settings().request_lifetime_secs.max(1) as i64;
        let response = {
            let mut book = lock(&self.book);
            let attempt = book.pairs.get(pair_id)
                .ok_or_else(|| CoreError::not_found("no such pairing request"))?;
            match reveal_attempt(attempt, &self.cert.sha256, &req, t, lifetime)? {
                Reveal::AlreadyRevealed => return Ok(PairResponse::Pending {
                    deny_reason: None, expires_at: Some(fmt_unix(attempt.expires)),
                }),
                Reveal::CommitmentMismatch => {
                    self.delete_book_row(pair_id)?;
                    book.pairs.remove(pair_id);
                    return Err(CoreError::invalid("client_nonce does not match the commitment"));
                }
                Reveal::Revealed(pending) => {
                    let mut attempt = attempt.clone();
                    attempt.state = PairState::Pending;
                    attempt.expires = pending.expires;
                    let response = PairResponse::Pending {
                        deny_reason: None, expires_at: Some(fmt_unix(pending.expires)),
                    };
                    let event = activity::requested(&pending);
                    self.save_pair_locked(&mut book, attempt, Some(pending), None)?;
                    self.log(event);
                    response
                }
            }
        };
        self.bump();
        self.notify(TOPIC_REQUESTS);
        Ok(response)
    }

    /// `GET /pair/{id}` (one check; the API layer long-polls).
    pub fn pair_poll(&self, pair_id: &str, poll_token: &str) -> Result<PairResponse> {
        self.expire_requests(now())?;
        let _authority = lock(&self.authorization);
        poll_attempt(&mut lock(&self.book), pair_id, poll_token, |host_id, token| {
            self.store.host_by_proof(host_id, &sha256(token.as_bytes()))?
                .ok_or_else(|| CoreError::not_found("no such pairing request"))?;
            self.delete_book_row(pair_id)
        })
    }

    /// Operator approved a pairing popup and hand the token to the poller:
    /// - re-pairing (`same_install`): the proven host gets a new token, its info and
    ///   address are refreshed, its name, leases and history stay;
    /// - `same_machine` with `replace`: the old host is revoked (with its leases) and a new
    ///   host takes over its friendly name;
    /// - otherwise a new host named `name` (see [`host_name`]).
    pub(crate) fn approve_pair(
        &self,
        p: &Pending,
        name: &str,
        replace: bool,
    ) -> std::result::Result<(), Fail> {
        let Detail::Pair {
            info,
            address,
            machine_hint,
            repair,
            ..
        } = &p.detail
        else {
            return Err(Fail::Keep(CoreError::invalid("not a pairing request")));
        };
        let t = now();
        let token = new_token();
        let token_hash = sha256(token.as_bytes());
        let mut host = HostRecord {
            id: new_uuid_v4(),
            info: info.clone(),
            name: String::new(),
            address: address.clone(),
            paired_at: t,
            last_seen: Some(t),
            revoked_at: None,
            machine_hint: machine_hint.clone(),
        };
        let rotated_proof = repair.as_ref().and_then(|r| r.proof.as_ref());
        let replacing = repair.as_ref().filter(|r| replace && r.proof.is_none());
        if let Some(previous) = repair.as_ref().filter(|r| r.proof.is_some() || replace) {
            // Use the current name, not the one that was shown when the popup opened.
            host.name = self.store.get_host(&previous.host_id)?
                .map_or_else(|| previous.host_name.clone(), |h| h.label().to_string());
            if rotated_proof.is_some() {
                host.id.clone_from(&previous.host_id);
            }
        } else {
            host.name = host_name(name, &info.hostname)?;
        }
        if let Some(previous) = replacing {
            // A forgeable hint never carries leases or tokens over.
            match self.revoke_host(&previous.host_id) {
                Ok(()) => {}
                Err(e) if e.code == asm_proto::ErrorCode::NotFound => {}
                Err(e) => return Err(Fail::Keep(e)),
            }
        }

        let approved = {
            let _authority = lock(&self.authorization);
            let mut book = lock(&self.book);
            let mut pending = book.pending.iter().find(|q| q.id == p.id && q.resolving && q.expires > now())
                .cloned().ok_or_else(|| CoreError::not_found("this pairing request is no longer pending"))?;
            pending.host_id = Some(host.id.clone());
            pending.host_label.clone_from(&host.name);
            let history = pending.history(RequestStatus::Approved, None, t);
            let mut attempt = book.pairs.get(&p.id).filter(|a| matches!(a.state, PairState::Pending))
                .cloned().ok_or_else(|| CoreError::internal("pairing request is missing its attempt"))?;
            attempt.state = PairState::Approved { host_id: host.id.clone(), token };
            attempt.ended = Some(t);
            let row = self.seal_pair(&attempt, None)?;
            if let Some(old_hash) = rotated_proof {
                if !self.store.rotate_host_token_with_request(&host, old_hash, &token_hash, &row, &history)? {
                    return Err(Fail::Keep(CoreError::invalid(format!(
                        "{} was revoked or paired again since this request; deny it and run asm pair again", host.name
                    ))));
                }
            } else {
                self.store.insert_host_with_request(&host, &token_hash, &row, &history)?;
            }
            Self::remove_pending_locked(&mut book, &p.id);
            book.pairs.insert(p.id.clone(), attempt);
            activity::approved(&pending, None, t)
        };
        if rotated_proof.is_some() {
            self.log(Event::new(Category::Pairing, "repaired",
                format!("{} paired again from {address}; its old token no longer works", host.name))
                .host(Some(&host.id)).detail(json!({
                    "request_id": p.id, "address": address, "host_info": info,
                })));
        } else if let Some(previous) = replacing {
            self.log(Event::new(Category::Pairing, "replaced",
                format!("{} paired from {address}, replacing the earlier host of that name (same machine hint); the earlier host and its leases were revoked", host.name))
                .host(Some(&host.id)).detail(json!({
                    "request_id": p.id, "replaced_host_id": previous.host_id, "address": address, "host_info": info,
                })));
        }
        self.log(approved);
        self.notify_request_ended();
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

    /// A code pairing without proof or machine hint.
    fn pair_with_code(
        store: &Store,
        cert: &[u8; 32],
        code: &str,
        info: HostInfo,
        ip: &str,
        t: i64,
    ) -> Result<CodePairing> {
        super::pair_with_code(store, cert, code, info, None, None, ip, t)
    }

    fn start_attempt(book: &mut Book, commit: &str, info: HostInfo, ip: &str, t: i64) -> Result<PairResponse> {
        let (attempt, response) = super::start_attempt(book, commit, info, ip, t)?;
        book.pairs.insert(attempt.id.clone(), attempt);
        Ok(response)
    }

    fn reveal_attempt(
        book: &mut Book, cert: &[u8; 32], id: &str, req: &RevealRequest, t: i64, lifetime: i64,
    ) -> Result<()> {
        let a = book.pairs.get_mut(id).unwrap();
        match super::reveal_attempt(a, cert, req, t, lifetime)? {
            Reveal::AlreadyRevealed => Ok(()),
            Reveal::CommitmentMismatch => {
                book.pairs.remove(id);
                Err(CoreError::invalid("client_nonce does not match the commitment"))
            }
            Reveal::Revealed(pending) => {
                a.state = PairState::Pending;
                a.expires = pending.expires;
                book.pending.push(pending);
                Ok(())
            }
        }
    }

    fn poll_attempt(book: &mut Book, id: &str, token: &str) -> Result<PairResponse> {
        super::poll_attempt(book, id, token, |_, _| Ok(()))
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
            ..
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
