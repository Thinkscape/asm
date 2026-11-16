//! `asm pair <hostname>[:port] [pairing-code]` (plan steps 5 and 8).

use crate::api::{Api, manager_url};
use crate::error::CliError;
use crate::state::{self, HostState};
use crate::tls::Pin;
use asm_proto::crypto::{hex_decode_array, hex_encode};
use asm_proto::pairing::{
    NONCE_LEN, UnattendedCode, client_commit, format_pairing_code, fp_prefix, new_nonce,
    pairing_code,
};
use asm_proto::wire::{
    HealthResponse, MANAGER_NAME, MAX_POLL_WAIT_SECS, PairRequest, PairResponse, RevealRequest,
};
use std::io::Write;

pub fn run(target: &str, code: Option<String>) -> Result<(), CliError> {
    let code = code
        .or_else(|| std::env::var("ASM_PAIRING_CODE").ok())
        .map(|c| c.trim().to_owned())
        .filter(|c| !c.is_empty());
    let code = code.as_deref().map(UnattendedCode::parse).transpose()?;
    let base = manager_url(target)?;

    // Every pairing call goes through one client pinned to the first certificate seen.
    let pin = Pin::first_seen();
    let api = Api::new(base.clone(), pin.clone(), None)?;
    let health: HealthResponse = api.get("/health")?;
    if health.name != MANAGER_NAME {
        return Err(CliError::failure(format!(
            "{base} is not an asm manager (it calls itself {:?})",
            health.name
        )));
    }
    let cert = pin
        .fingerprint()
        .expect("a TLS handshake recorded the certificate");

    let client_nonce = new_nonce();
    let request = PairRequest {
        client_commit: hex_encode(&client_commit(&client_nonce)),
        host_info: crate::hostinfo::collect(),
        pairing_code: None,
    };

    let approved = match code {
        Some(code) => {
            if !code.matches_cert(&cert) {
                return Err(CliError::failure(format!(
                    "the pairing code is for a manager certificate starting {}, but {base} presents {}; not sending it",
                    code.fp,
                    fp_prefix(&cert)
                )));
            }
            let request = PairRequest {
                pairing_code: Some(code.to_string()),
                ..request
            };
            match api.post::<_, PairResponse>("/pair", &request)? {
                PairResponse::Approved { host_id, token } => (host_id, token),
                other => return Err(unexpected(&other)),
            }
        }
        None => interactive(&api, &request, &cert, &client_nonce)?,
    };

    let (host_id, token) = approved;
    let host = HostState {
        manager_url: base,
        cert_sha256: hex_encode(&cert),
        host_id,
        token,
        paired_at: asm_proto::time::now_rfc3339(),
    };
    state::save(&host)?;
    match fetch_ca(&host) {
        Ok(()) => {}
        Err(e) => eprintln!(
            "warning: fetching the proxy CA failed ({}); run asm proxy-info later",
            e.message
        ),
    }
    println!("paired: {}", host.host_id);
    Ok(())
}

fn interactive(
    api: &Api,
    request: &PairRequest,
    cert: &[u8; 32],
    client_nonce: &[u8; NONCE_LEN],
) -> Result<(String, String), CliError> {
    let (pair_id, poll_token, server_nonce) = match api.post::<_, PairResponse>("/pair", request)? {
        PairResponse::AwaitingReveal {
            pair_id,
            poll_token,
            server_nonce,
        } => (pair_id, poll_token, server_nonce),
        other => return Err(unexpected(&other)),
    };
    let server_nonce: [u8; NONCE_LEN] = hex_decode_array(&server_nonce)
        .ok_or_else(|| CliError::failure("the manager sent an invalid server nonce"))?;
    if !pair_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(CliError::failure("the manager sent an invalid pair id"));
    }
    let code = pairing_code(cert, client_nonce, &server_nonce);
    let reveal = RevealRequest {
        poll_token: poll_token.clone(),
        client_nonce: hex_encode(client_nonce),
    };
    let started = std::time::Instant::now();
    let expires_at =
        match api.post::<_, PairResponse>(&format!("/pair/{pair_id}/reveal"), &reveal)? {
            PairResponse::Pending { expires_at, .. } => expires_at,
            other => return Err(unexpected(&other)),
        };
    // An unreachable manager is retried until the request would have expired there.
    let retry_until = started
        + crate::requests::pending_window(expires_at.as_deref(), 0, crate::requests::unix_now());
    println!("verification code: {}", format_pairing_code(code));
    eprintln!(
        "Check that the manager shows the same code, then approve the request there. Waiting…"
    );
    let _ = std::io::stdout().flush();

    let poll = format!(
        "/pair/{pair_id}?poll_token={}&wait={MAX_POLL_WAIT_SECS}",
        query_escape(&poll_token)
    );
    let mut backoff = crate::requests::Backoff::new();
    loop {
        let polled = std::time::Instant::now();
        let r = match api.get::<PairResponse>(&poll) {
            Ok(r) => r,
            Err(e) if e.transient => {
                if !backoff.wait(retry_until) {
                    return Err(CliError::lost_contact(
                        &e.message,
                        "the pairing request may still be pending on the manager: deny it there, then run asm pair again",
                    ));
                }
                continue;
            }
            Err(e) => return Err(e),
        };
        backoff.reset();
        match r {
            PairResponse::Pending { .. } => crate::requests::pace(polled),
            PairResponse::Approved { host_id, token } => return Ok((host_id, token)),
            PairResponse::Denied { deny_reason } => {
                return Err(CliError::denied(deny_reason.as_deref()));
            }
            PairResponse::Expired { .. } => {
                return Err(CliError::ended(
                    "expired: the pairing request was not approved in time",
                ));
            }
            other => return Err(unexpected(&other)),
        }
    }
}

fn fetch_ca(host: &HostState) -> Result<(), CliError> {
    let api = Api::for_host(host)?;
    let pem = api.get_bytes("/ca.crt")?;
    let pem =
        String::from_utf8(pem).map_err(|_| CliError::failure("the proxy CA is not PEM text"))?;
    crate::tls::pem_to_der(pem.as_bytes())
        .ok_or_else(|| CliError::failure("the proxy CA is not a PEM certificate"))?;
    state::write_ca_files(&pem)
}

fn unexpected(r: &PairResponse) -> CliError {
    let status = serde_json::to_value(r)
        .ok()
        .and_then(|v| v["status"].as_str().map(str::to_owned))
        .unwrap_or_default();
    CliError::failure(format!(
        "unexpected pairing status {status:?} from the manager"
    ))
}

/// Percent-encode everything outside the URL-safe unreserved set.
pub fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
