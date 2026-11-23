//! TOTP (RFC 6238) codes from a vault item's authenticator key. The key never leaves
//! the provider: only codes are handed out.

use ring::hmac;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, PartialEq, Eq)]
pub struct TotpKey {
    secret: Vec<u8>,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u64,
}

impl std::fmt::Debug for TotpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpKey")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish_non_exhaustive()
    }
}

/// With fewer seconds than this left in the current step, [`current_code`] returns the
/// next step's code, so a code typed now is not already stale on arrival.
const MIN_REMAINING_SECS: u64 = 5;

/// Parse an authenticator key: an `otpauth://totp/...` URI or a bare base32 secret.
pub fn parse(s: &str) -> Result<TotpKey, String> {
    let s = s.trim();
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("otpauth://hotp") || lower.starts_with("steam://") {
        return Err("unsupported authenticator key".into());
    }
    if lower.starts_with("otpauth://") {
        if !lower.starts_with("otpauth://totp/") && !lower.starts_with("otpauth://totp?") {
            return Err("unsupported authenticator key".into());
        }
        return parse_uri(s);
    }
    Ok(TotpKey {
        secret: decode_key(s)?,
        algorithm: TotpAlgorithm::Sha1,
        digits: 6,
        period: 30,
    })
}

fn parse_uri(s: &str) -> Result<TotpKey, String> {
    let query = s.split_once('?').map(|(_, q)| q).unwrap_or("");
    let query = query.split('#').next().unwrap_or("");
    let (mut secret, mut algorithm, mut digits, mut period) = (None, TotpAlgorithm::Sha1, 6, 30);
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v)?;
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(decode_key(&v)?),
            "algorithm" => {
                algorithm = match v.to_ascii_uppercase().as_str() {
                    "SHA1" => TotpAlgorithm::Sha1,
                    "SHA256" => TotpAlgorithm::Sha256,
                    "SHA512" => TotpAlgorithm::Sha512,
                    _ => return Err(format!("unsupported TOTP algorithm {v:?}")),
                }
            }
            "digits" => {
                digits = v
                    .parse::<u32>()
                    .ok()
                    .filter(|d| (6..=10).contains(d))
                    .ok_or_else(|| format!("TOTP digits must be 6 to 10, not {v:?}"))?
            }
            "period" => {
                period = v
                    .parse::<u64>()
                    .ok()
                    .filter(|p| (15..=300).contains(p))
                    .ok_or_else(|| format!("TOTP period must be 15 to 300 seconds, not {v:?}"))?
            }
            _ => {}
        }
    }
    Ok(TotpKey {
        secret: secret.ok_or("the authenticator URI has no secret")?,
        algorithm,
        digits,
        period,
    })
}

fn percent_decode(s: &str) -> Result<String, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = b
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or("invalid percent escape in the authenticator URI")?;
                out.push(hex);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| "the authenticator URI is not UTF-8".into())
}

/// Strip spaces, `-` and `=`, uppercase, then RFC 4648 base32-decode.
fn decode_key(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let secret = base32_decode(&cleaned).ok_or("the authenticator key is not valid base32")?;
    if secret.is_empty() {
        return Err("the authenticator key is empty".into());
    }
    Ok(secret)
}

/// RFC 4648 base32 (alphabet `A–Z2–7`, no padding). Leftover bits are dropped.
fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// RFC 6238 code for the step containing `unix`, zero-padded to `digits`.
pub fn code_at(key: &TotpKey, unix: u64) -> String {
    let counter = unix / key.period;
    let alg = match key.algorithm {
        TotpAlgorithm::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        TotpAlgorithm::Sha256 => hmac::HMAC_SHA256,
        TotpAlgorithm::Sha512 => hmac::HMAC_SHA512,
    };
    let tag = hmac::sign(&hmac::Key::new(alg, &key.secret), &counter.to_be_bytes());
    let mac = tag.as_ref();
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([mac[offset], mac[offset + 1], mac[offset + 2], mac[offset + 3]])
        & 0x7fff_ffff;
    let code = u64::from(bin) % 10u64.pow(key.digits);
    format!("{code:0width$}", width = key.digits as usize)
}

/// The code to hand out at `now`: the next step's when fewer than 5 s remain in the
/// current one. Never sleeps.
pub fn current_code(key: &TotpKey, now: u64) -> String {
    let remaining = key.period - now % key.period;
    if remaining < MIN_REMAINING_SECS {
        code_at(key, now + remaining)
    } else {
        code_at(key, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(secret: &[u8], algorithm: TotpAlgorithm) -> TotpKey {
        TotpKey { secret: secret.to_vec(), algorithm, digits: 8, period: 30 }
    }

    #[test]
    fn rfc6238_appendix_b() {
        let sha1 = key(b"12345678901234567890", TotpAlgorithm::Sha1);
        let sha256 = key(b"12345678901234567890123456789012", TotpAlgorithm::Sha256);
        let sha512 = key(
            b"1234567890123456789012345678901234567890123456789012345678901234",
            TotpAlgorithm::Sha512,
        );
        assert_eq!(code_at(&sha1, 59), "94287082");
        assert_eq!(code_at(&sha256, 59), "46119246");
        assert_eq!(code_at(&sha512, 59), "90693936");
        assert_eq!(code_at(&sha1, 1_111_111_109), "07081804");
        assert_eq!(code_at(&sha256, 1_111_111_109), "68084774");
        assert_eq!(code_at(&sha512, 1_111_111_109), "25091201");
    }

    #[test]
    fn current_code_moves_to_the_next_step_near_its_end() {
        let k = key(b"12345678901234567890", TotpAlgorithm::Sha1);
        let step_end = 30 * 37_037_037; // 1111111110
        assert_eq!(current_code(&k, step_end - 3), code_at(&k, step_end));
        assert_ne!(code_at(&k, step_end - 3), code_at(&k, step_end));
        assert_eq!(current_code(&k, step_end - 5), code_at(&k, step_end - 5));
        assert_eq!(current_code(&k, step_end), code_at(&k, step_end));
    }

    #[test]
    fn parses_uris_and_bare_keys() {
        let k = parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(k.secret, b"Hello!\xde\xad\xbe\xef");
        assert_eq!((k.algorithm, k.digits, k.period), (TotpAlgorithm::Sha1, 6, 30));
        let k = parse("otpauth://totp/Acme:me%40x.com?issuer=Acme&secret=jbsw%20y3dp&algorithm=sha512&digits=8&period=60")
            .unwrap();
        assert_eq!(k.secret, b"Hello");
        assert_eq!((k.algorithm, k.digits, k.period), (TotpAlgorithm::Sha512, 8, 60));
        assert_eq!(parse("jbsw y3dp-ehpk 3pxp====").unwrap().secret, b"Hello!\xde\xad\xbe\xef");
        assert_eq!(parse("otpauth://hotp/x?secret=JBSWY3DP").unwrap_err(), "unsupported authenticator key");
        assert_eq!(parse("steam://JBSWY3DP").unwrap_err(), "unsupported authenticator key");
        assert!(parse("otpauth://totp/x?issuer=a").is_err());
        assert!(parse("otpauth://totp/x?secret=JBSWY3DP&digits=5").is_err());
        assert!(parse("otpauth://totp/x?secret=JBSWY3DP&period=10").is_err());
        assert!(parse("otpauth://totp/x?secret=JBSWY3DP&algorithm=MD5").is_err());
        assert!(parse("not base32!").is_err());
        assert!(parse("").is_err());
    }
}
