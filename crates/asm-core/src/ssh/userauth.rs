//! Strict parsing of the data an SSH client asks an agent to sign for public-key
//! user authentication (RFC 4252 §7, OpenSSH `publickey-hostbound-v00@openssh.com`).

use asm_proto::ssh::{PRIVILEGED_LOGIN, RESTRICTED_LOGIN, Reader};

const USERAUTH_REQUEST: u8 = 50;
const SERVICE: &[u8] = b"ssh-connection";
const PUBLICKEY: &[u8] = b"publickey";
const PUBLICKEY_HOSTBOUND: &[u8] = b"publickey-hostbound-v00@openssh.com";

#[derive(Debug)]
pub(crate) struct Userauth<'a> {
    pub user: &'a str,
    pub alg: &'a str,
    pub key_blob: &'a [u8],
    /// The server host key blob of a `publickey-hostbound-v00@openssh.com` request.
    pub host_key: Option<&'a [u8]>,
}

/// Accept only a complete public-key userauth request; anything else (SSHSIG
/// payloads, other services, trailing bytes) is refused.
pub(crate) fn parse_userauth(data: &[u8]) -> Result<Userauth<'_>, &'static str> {
    const NOT: &str = "not an SSH user authentication request";
    let mut r = Reader::new(data);
    let session_id = r.string().ok_or(NOT)?;
    if session_id.is_empty() || session_id.len() > 64 {
        return Err(NOT);
    }
    if r.u8().ok_or(NOT)? != USERAUTH_REQUEST {
        return Err(NOT);
    }
    let user = std::str::from_utf8(r.string().ok_or(NOT)?).map_err(|_| "invalid login name")?;
    if user != RESTRICTED_LOGIN && user != PRIVILEGED_LOGIN {
        return Err("invalid login name");
    }
    if r.string().ok_or(NOT)? != SERVICE {
        return Err("unexpected SSH service");
    }
    let method = r.string().ok_or(NOT)?;
    let hostbound = match method {
        PUBLICKEY => false,
        PUBLICKEY_HOSTBOUND => true,
        _ => return Err("unexpected authentication method"),
    };
    if !r.bool().ok_or(NOT)? {
        return Err("not a signature request");
    }
    let alg = std::str::from_utf8(r.string().ok_or(NOT)?).map_err(|_| "invalid key algorithm")?;
    let key_blob = r.string().ok_or(NOT)?;
    let host_key = if hostbound {
        let key = r.string().ok_or(NOT)?;
        if key.is_empty() {
            return Err("missing host key");
        }
        Some(key)
    } else {
        None
    };
    if !r.is_empty() {
        return Err("trailing data after the authentication request");
    }
    Ok(Userauth { user, alg, key_blob, host_key })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use asm_proto::ssh::{put_string, put_u32};

    /// A userauth payload as OpenSSH builds it before asking the agent to sign.
    pub(crate) fn payload(user: &str, method: &str, has_signature: bool, alg: &str, key: &[u8], extra: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(&mut out, &[7u8; 32]);
        out.push(USERAUTH_REQUEST);
        put_string(&mut out, user.as_bytes());
        put_string(&mut out, SERVICE);
        put_string(&mut out, method.as_bytes());
        out.push(has_signature as u8);
        put_string(&mut out, alg.as_bytes());
        put_string(&mut out, key);
        if method.as_bytes() == PUBLICKEY_HOSTBOUND {
            put_string(&mut out, b"hostkey-blob");
        }
        out.extend_from_slice(extra);
        out
    }

    /// A `publickey-hostbound-v00@openssh.com` payload for the server host key `host_key`.
    pub(crate) fn hostbound_payload(user: &str, alg: &str, key: &[u8], host_key: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(&mut out, &[7u8; 32]);
        out.push(USERAUTH_REQUEST);
        put_string(&mut out, user.as_bytes());
        put_string(&mut out, SERVICE);
        put_string(&mut out, PUBLICKEY_HOSTBOUND);
        out.push(1);
        put_string(&mut out, alg.as_bytes());
        put_string(&mut out, key);
        put_string(&mut out, host_key);
        out
    }

    #[test]
    fn accepts_publickey_and_hostbound_requests() {
        let alg = "ssh-ed25519-cert-v01@openssh.com";
        let plain = payload("asm-priv", "publickey", true, alg, b"cert", b"");
        let parsed = parse_userauth(&plain).unwrap();
        assert_eq!((parsed.user, parsed.alg, parsed.key_blob, parsed.host_key), ("asm-priv", alg, &b"cert"[..], None));
        let bound = payload("asm-ops", "publickey-hostbound-v00@openssh.com", true, alg, b"cert", b"");
        let parsed = parse_userauth(&bound).unwrap();
        assert_eq!((parsed.user, parsed.host_key), ("asm-ops", Some(&b"hostkey-blob"[..])));
    }

    #[test]
    fn refuses_other_payloads() {
        let alg = "ssh-ed25519-cert-v01@openssh.com";
        assert!(parse_userauth(&payload("asm-ops", "publickey", true, alg, b"cert", b"x")).is_err());
        assert!(parse_userauth(&payload("asm-ops", "publickey", false, alg, b"cert", b"")).is_err());
        assert!(parse_userauth(&payload("asm-ops", "password", true, alg, b"cert", b"")).is_err());
        for user in ["root", "deploy", "asm-x", "Root!"] {
            assert_eq!(parse_userauth(&payload(user, "publickey", true, alg, b"cert", b"")).unwrap_err(),
                "invalid login name", "{user}");
        }
        let mut other_service = Vec::new();
        put_string(&mut other_service, &[7u8; 32]);
        other_service.push(USERAUTH_REQUEST);
        put_string(&mut other_service, b"asm-ops");
        put_string(&mut other_service, b"ssh-userauth");
        assert!(parse_userauth(&other_service).is_err());
        // An SSHSIG blob (git commit signing) starts with the magic preamble.
        let mut sshsig = b"SSHSIG".to_vec();
        put_u32(&mut sshsig, 1);
        put_string(&mut sshsig, b"git");
        assert!(parse_userauth(&sshsig).is_err());
        assert!(parse_userauth(&[]).is_err());
    }
}
