//! Proxy CA: generation through `iron-proxy generate-ca`, PEM/DER access, expiry.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine as _;

use crate::error::{CoreError, Result};

pub const CA_NAME: &str = "Agents Secrets Manager Proxy CA";
pub const CA_EXPIRY_HOURS: u32 = 87_600;

pub struct CaPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl CaPaths {
    pub fn new(proxy_dir: &Path) -> Self {
        Self {
            cert: proxy_dir.join("ca.crt"),
            key: proxy_dir.join("ca.key"),
        }
    }
}

/// Create the CA when both files are absent (a lone leftover is deleted first).
pub fn ensure(binary: &Path, proxy_dir: &Path) -> Result<CaPaths> {
    let p = CaPaths::new(proxy_dir);
    match (p.cert.exists(), p.key.exists()) {
        (true, true) => return Ok(p),
        (true, false) => std::fs::remove_file(&p.cert)?,
        (false, true) => std::fs::remove_file(&p.key)?,
        (false, false) => {}
    }
    let out = Command::new(binary)
        .arg("generate-ca")
        .arg("-outdir")
        .arg(proxy_dir)
        .arg("-name")
        .arg(CA_NAME)
        .arg("-expiry-hours")
        .arg(CA_EXPIRY_HOURS.to_string())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| {
            CoreError::internal(format!("cannot run {} generate-ca: {e}", binary.display()))
        })?;
    if !out.status.success() || !p.cert.exists() || !p.key.exists() {
        let _ = std::fs::remove_file(&p.cert);
        let _ = std::fs::remove_file(&p.key);
        return Err(CoreError::internal(format!(
            "iron-proxy generate-ca failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(p)
}

/// DER bytes of the first `CERTIFICATE` block of a PEM document.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = pem
        .find(BEGIN)
        .ok_or_else(|| CoreError::internal("CA file holds no certificate"))?
        + BEGIN.len();
    let end = pem[start..]
        .find(END)
        .ok_or_else(|| CoreError::internal("CA certificate PEM is truncated"))?
        + start;
    let b64: String = pem[start..end]
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| CoreError::internal(format!("CA certificate PEM is invalid: {e}")))
}

/// One DER TLV at `pos`: (tag, content range).
fn tlv(buf: &[u8], pos: usize) -> Option<(u8, std::ops::Range<usize>)> {
    let tag = *buf.get(pos)?;
    let first = *buf.get(pos + 1)? as usize;
    let (len, hdr) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *buf.get(pos + 2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let start = pos + hdr;
    let end = start.checked_add(len)?;
    (end <= buf.len()).then_some((tag, start..end))
}

/// `notAfter` of an X.509 certificate as RFC 3339 UTC.
pub fn not_after(der: &[u8]) -> Option<String> {
    let (t, cert) = tlv(der, 0)?;
    if t != 0x30 {
        return None;
    }
    let (t, tbs) = tlv(der, cert.start)?;
    if t != 0x30 {
        return None;
    }
    let mut pos = tbs.start;
    // [0] version (optional), serialNumber, signature, issuer, then validity.
    let (t, r) = tlv(der, pos)?;
    if t == 0xa0 {
        pos = r.end;
    }
    for _ in 0..3 {
        pos = tlv(der, pos)?.1.end;
    }
    let (t, validity) = tlv(der, pos)?;
    if t != 0x30 {
        return None;
    }
    let not_before = tlv(der, validity.start)?.1;
    let (t, na) = tlv(der, not_before.end)?;
    let s = std::str::from_utf8(&der[na]).ok()?;
    let full = match (t, s.len()) {
        (0x17, 13) => {
            let yy: u32 = s[..2].parse().ok()?;
            format!("{}{}", if yy >= 50 { 19 } else { 20 }, s)
        }
        (0x18, 15) => s.to_string(),
        _ => return None,
    };
    let b = full.as_bytes();
    if b[14] != b'Z' || !b[..14].iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(format!(
        "{}-{}-{}T{}:{}:{}Z",
        &full[0..4],
        &full[4..6],
        &full[6..8],
        &full[8..10],
        &full[10..12],
        &full[12..14]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_pem(year: i32) -> String {
        let mut params = rcgen::CertificateParams::new(vec!["test".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(year, 3, 4);
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    #[test]
    fn parses_not_after_utctime_and_generalized() {
        let der = pem_to_der(&cert_pem(2035)).unwrap();
        assert_eq!(not_after(&der).as_deref(), Some("2035-03-04T00:00:00Z"));
        // Years from 2050 on are encoded as GeneralizedTime.
        let der = pem_to_der(&cert_pem(2061)).unwrap();
        assert_eq!(not_after(&der).as_deref(), Some("2061-03-04T00:00:00Z"));
    }

    #[test]
    fn rejects_garbage() {
        assert!(pem_to_der("nothing").is_err());
        assert_eq!(not_after(&[0x30, 0x03, 0x02, 0x01, 0x00]), None);
        assert_eq!(not_after(&[]), None);
    }
}
