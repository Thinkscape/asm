//! The asm browser CA: a dedicated root that iron-proxy issues leaves from only for
//! routed, granted browser `(host, port)` pairs. Browsers install it once, so it is
//! created once and never rotated.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use asm_proto::crypto::random_bytes;
use asm_proto::time::fmt_unix;

use super::ca::CaPaths;
use super::files::write_private_atomic;
use crate::error::{CoreError, Result};

pub const BROWSER_CA_NAME: &str = "Agents Secrets Manager Browser CA";
const CERT_FILE: &str = "browser-ca.crt";
const KEY_FILE: &str = "browser-ca.key";
const VALIDITY_YEARS: i32 = 10;

pub fn paths(proxy_dir: &Path) -> CaPaths {
    CaPaths {
        cert: proxy_dir.join(CERT_FILE),
        key: proxy_dir.join(KEY_FILE),
    }
}

/// Create the browser CA when both files are absent (a lone leftover is deleted first).
pub fn ensure(proxy_dir: &Path) -> Result<CaPaths> {
    let p = paths(proxy_dir);
    match (p.cert.exists(), p.key.exists()) {
        (true, true) => return Ok(p),
        (true, false) => std::fs::remove_file(&p.cert)?,
        (false, true) => std::fs::remove_file(&p.key)?,
        (false, false) => {}
    }
    let (cert_pem, key_pem) = generate(crate::manager::now())?;
    write_private_atomic(proxy_dir, KEY_FILE, key_pem.as_bytes())?;
    let written = write_private_atomic(proxy_dir, CERT_FILE, cert_pem.as_bytes())
        .and_then(|path| std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&p.cert);
        let _ = std::fs::remove_file(&p.key);
        return Err(e.into());
    }
    Ok(p)
}

/// `(year, month, day)` of a Unix time, UTC.
fn ymd(unix: i64) -> (i32, u8, u8) {
    let s = fmt_unix(unix);
    let part = |r: std::ops::Range<usize>| s.get(r).and_then(|v| v.parse::<i32>().ok()).unwrap_or(1);
    (part(0..4), part(5..7) as u8, part(8..10) as u8)
}

/// Self-signed ECDSA P-256 CA certificate and key (PEM), valid from a day before `now`
/// for ten years, unable to sign intermediates (path length 0).
fn generate(now: i64) -> Result<(String, String)> {
    let err = |e: rcgen::Error| CoreError::internal(format!("browser CA: {e}"));
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(err)?;
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, BROWSER_CA_NAME);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let (y, m, d) = ymd(now - 86_400);
    params.not_before = rcgen::date_time_ymd(y, m, d);
    let (y, m, d) = ymd(now);
    // 29 February does not exist in most target years.
    let d = if m == 2 && d == 29 { 28 } else { d };
    params.not_after = rcgen::date_time_ymd(y + VALIDITY_YEARS, m, d);
    let mut serial = random_bytes::<16>();
    // A positive, non-zero DER integer of full length.
    serial[0] = (serial[0] & 0x7f) | 0x01;
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
    let cert = params.self_signed(&key).map_err(err)?;
    Ok((cert.pem(), key.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn ensure_creates_a_path_length_zero_ca_once() {
        let dir = tempfile::tempdir().unwrap();
        let p = ensure(dir.path()).unwrap();
        let pem = std::fs::read_to_string(&p.cert).unwrap();
        let der = super::super::ca::pem_to_der(&pem).unwrap();
        // basicConstraints (2.5.29.19), critical, {cA TRUE, pathLenConstraint 0}.
        assert!(contains(&der, &[0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08,
            0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00]));
        assert!(contains(&der, BROWSER_CA_NAME.as_bytes()));
        let expiry = super::super::ca::not_after(&der).unwrap();
        let year: i32 = expiry[..4].parse().unwrap();
        assert_eq!(year, ymd(crate::manager::now()).0 + VALIDITY_YEARS);
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&p.cert), 0o644);
        assert_eq!(mode(&p.key), 0o600);

        let key = std::fs::read(&p.key).unwrap();
        ensure(dir.path()).unwrap();
        assert_eq!(std::fs::read_to_string(&p.cert).unwrap(), pem, "idempotent");
        assert_eq!(std::fs::read(&p.key).unwrap(), key);

        std::fs::remove_file(&p.key).unwrap();
        ensure(dir.path()).unwrap();
        assert_ne!(std::fs::read_to_string(&p.cert).unwrap(), pem, "a half-present CA is regenerated");
        assert!(p.key.exists());
    }
}
