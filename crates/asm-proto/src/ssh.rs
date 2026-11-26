//! SSH leases: wire types, SSH binary encoding helpers and shared validators.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// The fixed account restricted access logs in as.
pub const RESTRICTED_LOGIN: &str = "asm-ops";
/// The fixed account privileged access logs in as; it runs commands as the target's
/// privileged login through sudo.
pub const PRIVILEGED_LOGIN: &str = "asm-priv";
/// Most targets one request may name.
pub const MAX_TARGETS: usize = 16;
/// Most grants one restricted request may name.
pub const MAX_GRANTS: usize = 16;
/// Most other users one target may let agents log in as.
pub const MAX_USERS: usize = 16;
/// Largest data a sign request may carry, decoded.
pub const MAX_SIGN_DATA: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshAccess {
    /// A shell as the target's privileged login (`asm-priv` through sudo).
    Privileged,
    /// `asm-ops`, which runs only the granted operations.
    Restricted,
    /// A shell as one of the other users the target allows (`asm-priv` through sudo).
    User,
}

impl SshAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Privileged => "privileged",
            Self::Restricted => "restricted",
            Self::User => "user",
        }
    }

    /// The account the lease's certificate logs in as.
    pub fn login(self) -> &'static str {
        match self {
            Self::Privileged | Self::User => PRIVILEGED_LOGIN,
            Self::Restricted => RESTRICTED_LOGIN,
        }
    }
}

/// Result of an approved SSH request: the hosts the operator approved, each with its own
/// access. Hosts the operator denied are absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshResult {
    pub lease_id: String,
    /// RFC 3339.
    pub expires_at: String,
    pub targets: Vec<SshTargetAccess>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshTargetAccess {
    pub name: String,
    pub target_id: String,
    /// The account the certificate logs in as (`asm-ops` or `asm-priv`).
    pub login: String,
    pub hostname: String,
    pub port: u16,
    /// `"<type> <b64>"`.
    pub host_keys: Vec<String>,
    pub access: SshAccess,
    /// The operations of restricted access.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<String>,
    /// The user access as a user runs as.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// One OpenSSH certificate line, for this host only.
    pub certificate: String,
}

/// `POST /v1/ssh/sign`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshSignRequest {
    pub lease_id: String,
    /// Standard base64 of the data to sign.
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshSignResponse {
    /// Standard base64 of the SSH signature blob.
    pub signature: String,
}

/// `GET /v1/ssh/targets`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshTargetsResponse {
    pub targets: Vec<SshTargetSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshTargetSummary {
    pub name: String,
    /// The login privileged leases run as; `None` when the host doesn't allow privileged access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged_login: Option<String>,
    /// The other users agents may log in as.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<String>,
    /// Every grant the target allows.
    pub grants: Vec<String>,
}

// ---- SSH binary encoding ----

pub fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// An SSH `string`: a big-endian `u32` length, then the bytes.
pub fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

/// Reads SSH wire values; every read is `None` on truncated input.
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.data.len() < n {
            return None;
        }
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        Some(head)
    }

    pub fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    pub fn bool(&mut self) -> Option<bool> {
        Some(self.u8()? != 0)
    }

    pub fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

pub fn b64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn b64_decode(text: &str) -> Option<Vec<u8>> {
    STANDARD.decode(text).ok()
}

// ---- validators ----

/// A lowercase DNS host name or IPv4 address, at most 253 characters:
/// labels `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` joined by '.'.
pub fn validate_target_name(name: &str) -> Result<(), ApiError> {
    let label_ok = |l: &str| {
        let b = l.as_bytes();
        !b.is_empty()
            && b.len() <= 63
            && b[0] != b'-'
            && b[b.len() - 1] != b'-'
            && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
    };
    if !name.is_empty() && name.len() <= 253 && name.split('.').all(label_ok) {
        Ok(())
    } else {
        Err(ApiError::invalid(format!(
            "invalid SSH host name {name:?}: use a lowercase host name or address such as web.example.com"
        )))
    }
}

/// A login on a target (the privileged login, or another user agents may log in as):
/// `^[a-z_][a-z0-9_-]{0,31}$`, not starting with `asm-`.
pub fn validate_login(login: &str) -> Result<(), ApiError> {
    let b = login.as_bytes();
    let ok = !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-');
    if !ok {
        return Err(ApiError::invalid(format!(
            "invalid login {login:?}: use 1–32 lowercase letters, digits, '_' or '-', starting with a letter or '_'"
        )));
    }
    if login.starts_with("asm-") {
        return Err(ApiError::invalid("logins starting with asm- are reserved for asm's accounts"));
    }
    Ok(())
}

/// A systemd service name: `^[A-Za-z0-9][A-Za-z0-9@._-]{0,120}\.service$`.
pub fn validate_unit(unit: &str) -> Result<(), ApiError> {
    let ok = unit.strip_suffix(".service").is_some_and(|stem| {
        let b = stem.as_bytes();
        !b.is_empty()
            && b.len() <= 121
            && b[0].is_ascii_alphanumeric()
            && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'@' | b'.' | b'_' | b'-'))
    });
    if ok {
        Ok(())
    } else {
        Err(ApiError::invalid(format!("invalid unit {unit:?}: expected a name like web.service")))
    }
}

/// `logs:<unit>`, `restart:<unit>`, `reload:<unit>` or `read:<path>`.
pub fn validate_grant(grant: &str) -> Result<(), ApiError> {
    if let Some(unit) = grant_unit(grant) {
        return validate_unit(unit);
    }
    match grant.strip_prefix("read:") {
        Some(path) => validate_read_path(path),
        None => Err(ApiError::invalid(format!(
            "unknown grant {grant:?}; use logs:<unit>, restart:<unit>, reload:<unit> or read:<path>"
        ))),
    }
}

/// The unit of a `logs:`, `restart:` or `reload:` grant.
pub fn grant_unit(grant: &str) -> Option<&str> {
    grant.strip_prefix("logs:").or_else(|| grant.strip_prefix("restart:")).or_else(|| grant.strip_prefix("reload:"))
}

/// A file restricted access may read: absolute, at most 255 bytes, components of
/// `[A-Za-z0-9._@+-]` that are neither empty, `.` nor `..`.
pub fn validate_read_path(path: &str) -> Result<(), ApiError> {
    let ok = path.len() <= 255
        && path.strip_prefix('/').is_some_and(|rest| {
            rest.split('/').all(|c| {
                !c.is_empty()
                    && c != "."
                    && c != ".."
                    && c.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'+' | b'-'))
            })
        });
    if ok {
        Ok(())
    } else {
        Err(ApiError::invalid(format!("invalid file {path:?}: use an absolute path such as /etc/nginx/nginx.conf")))
    }
}

/// The grants and user `access` takes: 1–`MAX_GRANTS` valid grants for restricted access
/// and none otherwise; a valid user for access as a user and none otherwise.
pub fn validate_access(access: SshAccess, grants: &[String], user: Option<&str>) -> Result<(), ApiError> {
    if access == SshAccess::Restricted {
        if grants.is_empty() || grants.len() > MAX_GRANTS {
            return Err(ApiError::invalid(format!("restricted access needs 1–{MAX_GRANTS} grants")));
        }
        for grant in grants {
            validate_grant(grant)?;
        }
    } else if !grants.is_empty() {
        return Err(ApiError::invalid("grants apply only to restricted access"));
    }
    match (access, user) {
        (SshAccess::User, Some(user)) => validate_login(user),
        (SshAccess::User, None) => Err(ApiError::invalid("access as a user needs the user's name")),
        (_, Some(_)) => Err(ApiError::invalid("a user applies only to access as a user")),
        (_, None) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validators_accept_and_reject_boundaries() {
        for good in ["a", "web.example.com", "10.0.0.5", "prod-web-1", &"a".repeat(63)] {
            assert!(validate_target_name(good).is_ok(), "{good}");
        }
        let long = format!("{}.{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(62));
        assert_eq!(long.len(), 254);
        for bad in ["", "-a", "a.", ".a", "a..b", "A", "a_b", "web example", &"a".repeat(64), &long] {
            assert!(validate_target_name(bad).is_err(), "{bad}");
        }
        for good in ["root", "_svc", "deploy-1", "a_b-c", &format!("a{}", "b".repeat(31))] {
            assert!(validate_login(good).is_ok(), "{good}");
        }
        for bad in ["", "1root", "Root", "asm-ops", "asm-priv", "asm-x", "a b", &format!("a{}", "b".repeat(32))] {
            assert!(validate_login(bad).is_err(), "{bad}");
        }
        for good in ["web.service", "a.service", "getty@tty1.service", "my_app-2.x.service"] {
            assert!(validate_unit(good).is_ok(), "{good}");
        }
        let long = format!("a{}.service", "b".repeat(120));
        assert!(validate_unit(&long).is_ok());
        let too_long = format!("a{}.service", "b".repeat(121));
        for bad in [".service", "web", "web.socket", "-a.service", "a:b.service", "a b.service", too_long.as_str()] {
            assert!(validate_unit(bad).is_err(), "{bad}");
        }
        for good in ["logs:web.service", "restart:web.service", "reload:web.service", "read:/etc/nginx/nginx.conf"] {
            assert!(validate_grant(good).is_ok(), "{good}");
        }
        for bad in ["logs", "logs:", "log", "restart:", "restart:web", "reload:web", "shell", "restart:web.service x",
            "read:", "read:etc/x", "status:web.service"] {
            assert!(validate_grant(bad).is_err(), "{bad}");
        }
        assert_eq!(grant_unit("reload:a.service"), Some("a.service"));
        assert_eq!(grant_unit("read:/a"), None);
        let max = format!("/{}", "a".repeat(254));
        for good in ["/a", "/etc/nginx/nginx.conf", "/srv/app/.env", "/var/log/a@b+c-d_e.log", "/a/..b", max.as_str()] {
            assert!(validate_read_path(good).is_ok(), "{good}");
        }
        let too_long = format!("/{}", "a".repeat(255));
        for bad in ["", "/", "a", "//a", "/a/", "/a//b", "/a/./b", "/a/../b", "/..", "/a b", "/a*", "/a\nb", "/a:b",
            "/a,b", "/a\\b", too_long.as_str()] {
            assert!(validate_read_path(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn reader_round_trips_writes() {
        let mut out = Vec::new();
        out.push(7);
        put_u32(&mut out, 0xdead_beef);
        put_u64(&mut out, u64::MAX - 1);
        put_string(&mut out, b"hello");
        out.push(1);
        let mut r = Reader::new(&out);
        assert_eq!(r.u8(), Some(7));
        assert_eq!(r.u32(), Some(0xdead_beef));
        assert_eq!(r.u64(), Some(u64::MAX - 1));
        assert_eq!(r.string(), Some(&b"hello"[..]));
        assert_eq!(r.bool(), Some(true));
        assert!(r.is_empty());
        assert!(r.u8().is_none());
        let mut short = Reader::new(&[0, 0, 0, 9, 1, 2]);
        assert!(short.string().is_none());
        assert_eq!(b64_decode(&b64_encode(b"\x00\xffabc")), Some(b"\x00\xffabc".to_vec()));
        assert_eq!(b64_decode("not base64!"), None);
    }
}
