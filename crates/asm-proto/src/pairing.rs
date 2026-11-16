//! Pairing: commit-and-reveal verification codes and unattended pairing codes.

use crate::crypto::{base32_lower_encode, ct_eq, hex_encode, random_bytes, sha256};
use crate::error::ApiError;

/// Length of client and server nonces in bytes (32 hex characters on the wire).
pub const NONCE_LEN: usize = 16;
/// Length of the unattended code secret in base32 characters (16 random bytes).
pub const UNATTENDED_SECRET_LEN: usize = 26;
/// Length of the fingerprint prefix in an unattended code, in hex characters.
pub const UNATTENDED_FP_LEN: usize = 16;

/// A fresh random nonce.
pub fn new_nonce() -> [u8; NONCE_LEN] {
    random_bytes()
}

/// SHA-256 of the DER certificate, i.e. the pinned fingerprint.
pub fn cert_fingerprint(cert_der: &[u8]) -> [u8; 32] {
    sha256(cert_der)
}

/// The client's commitment: `SHA-256(client_nonce)`.
pub fn client_commit(client_nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
    sha256(client_nonce)
}

/// Check a revealed nonce against the commitment (constant time).
pub fn verify_commit(commit: &[u8; 32], client_nonce: &[u8; NONCE_LEN]) -> bool {
    ct_eq(commit, &client_commit(client_nonce))
}

/// The verification code both sides show: big-endian first 4 bytes of
/// `SHA-256(cert_sha256 || client_nonce || server_nonce)` mod 1,000,000.
pub fn pairing_code(cert_sha256: &[u8; 32], client_nonce: &[u8; NONCE_LEN], server_nonce: &[u8; NONCE_LEN]) -> u32 {
    let mut buf = [0u8; 32 + 2 * NONCE_LEN];
    buf[..32].copy_from_slice(cert_sha256);
    buf[32..48].copy_from_slice(client_nonce);
    buf[48..].copy_from_slice(server_nonce);
    let h = sha256(buf);
    u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % 1_000_000
}

/// Display form of a verification code: zero-padded, `123 456`.
pub fn format_pairing_code(code: u32) -> String {
    format!("{:03} {:03}", code / 1000 % 1000, code % 1000)
}

/// An unattended pairing code `asm-<secret>-<fp>`: `secret` is 26 lowercase base32
/// characters, `fp` the first 16 hex characters of the manager certificate fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnattendedCode {
    pub secret: String,
    pub fp: String,
}

impl UnattendedCode {
    /// Generate a code for the manager certificate with this fingerprint.
    pub fn generate(cert_sha256: &[u8; 32]) -> Self {
        UnattendedCode {
            secret: base32_lower_encode(&random_bytes::<16>()),
            fp: fp_prefix(cert_sha256),
        }
    }

    /// Parse `asm-<26 base32>-<16 hex>` (case-insensitive, surrounding whitespace ignored).
    pub fn parse(code: &str) -> Result<Self, ApiError> {
        let bad = || ApiError::invalid("pairing code must look like asm-<26 characters>-<16 hex digits>");
        let code = code.trim().to_ascii_lowercase();
        let rest = code.strip_prefix("asm-").ok_or_else(bad)?;
        let (secret, fp) = rest.split_once('-').ok_or_else(bad)?;
        let secret_ok = secret.len() == UNATTENDED_SECRET_LEN
            && secret.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b));
        let fp_ok = fp.len() == UNATTENDED_FP_LEN && fp.bytes().all(|b| b.is_ascii_hexdigit());
        if !secret_ok || !fp_ok {
            return Err(bad());
        }
        Ok(UnattendedCode { secret: secret.to_owned(), fp: fp.to_owned() })
    }

    /// True when the fingerprint prefix matches this certificate fingerprint.
    /// The CLI must check this before sending the code.
    pub fn matches_cert(&self, cert_sha256: &[u8; 32]) -> bool {
        self.fp == fp_prefix(cert_sha256)
    }

    /// `SHA-256(secret)` (of the 26 ASCII characters): what the manager stores.
    pub fn secret_sha256(&self) -> [u8; 32] {
        sha256(self.secret.as_bytes())
    }
}

impl std::fmt::Display for UnattendedCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "asm-{}-{}", self.secret, self.fp)
    }
}

/// First 16 lowercase hex characters of a certificate fingerprint.
pub fn fp_prefix(cert_sha256: &[u8; 32]) -> String {
    hex_encode(&cert_sha256[..UNATTENDED_FP_LEN / 2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_the_same_code() {
        let cert = sha256(b"cert der");
        let (cn, sn) = (new_nonce(), new_nonce());
        let client = pairing_code(&cert, &cn, &sn);
        let manager = pairing_code(&cert, &cn, &sn);
        assert_eq!(client, manager);
        assert!(client < 1_000_000);
        assert!(verify_commit(&client_commit(&cn), &cn));
    }

    #[test]
    fn relay_cannot_match_codes() {
        let cert = sha256(b"cert der");
        let relay_cert = sha256(b"relay cert der");
        let (cn, sn) = (new_nonce(), new_nonce());
        let relay_nonce = new_nonce();
        // Relay substitutes its own nonce toward the manager: the commit no longer verifies.
        assert!(!verify_commit(&client_commit(&cn), &relay_nonce));
        // Different server nonce or certificate → different code (overwhelmingly likely).
        let differs = (0..8).any(|_| pairing_code(&cert, &cn, &sn) != pairing_code(&cert, &cn, &new_nonce()));
        assert!(differs);
        assert_ne!(pairing_code(&cert, &cn, &sn), pairing_code(&relay_cert, &cn, &sn));
    }

    #[test]
    fn known_vector_and_display() {
        let code = pairing_code(&[0; 32], &[0; 16], &[0; 16]);
        let h = sha256([0u8; 64]);
        assert_eq!(code, u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % 1_000_000);
        assert_eq!(format_pairing_code(7), "000 007");
        assert_eq!(format_pairing_code(123_456), "123 456");
    }

    #[test]
    fn unattended_codes() {
        let cert = sha256(b"cert der");
        let code = UnattendedCode::generate(&cert);
        let s = code.to_string();
        assert_eq!(s.len(), 4 + 26 + 1 + 16);
        let parsed = UnattendedCode::parse(&format!(" {} ", s.to_uppercase())).unwrap();
        assert_eq!(parsed, code);
        assert!(parsed.matches_cert(&cert));
        assert!(!parsed.matches_cert(&sha256(b"other")));
        assert_eq!(parsed.secret_sha256(), sha256(code.secret.as_bytes()));
        assert!(UnattendedCode::parse("asm-short-0123456789abcdef").is_err());
        assert!(UnattendedCode::parse(&s.replacen("asm-", "xyz-", 1)).is_err());
    }
}
