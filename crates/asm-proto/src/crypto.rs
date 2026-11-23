//! Randomness, ids, tokens, hashing and encodings shared by manager and CLI.

use sha2::{Digest, Sha256};

/// `N` bytes from the operating system's CSPRNG. Panics if the OS RNG fails.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("operating system random number generator failed");
    buf
}

/// A random UUIDv4 in lowercase hyphenated form.
pub fn new_uuid_v4() -> String {
    let mut b: [u8; 16] = random_bytes();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex_encode(&b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// True when `s` is a hyphenated UUID (any version, either case).
pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// A bearer/poll token: 32 random bytes, base64url without padding.
pub fn new_token() -> String {
    base64url_encode(&random_bytes::<32>())
}

/// SHA-256 digest.
pub fn sha256(data: impl AsRef<[u8]>) -> [u8; 32] {
    Sha256::digest(data.as_ref()).into()
}

/// Lowercase hex of SHA-256 (e.g. certificate fingerprints, `ca_sha256`).
pub fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    hex_encode(&sha256(data))
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&sha256(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// Proxy-authentication password of a paired host, derived from the SHA-256 of
/// its bearer token. Manager and CLI derive it independently; the token itself
/// never reaches the proxy.
pub fn proxy_password(token_hash: &[u8; 32]) -> String {
    hex_encode(&hmac_sha256(token_hash, b"asm proxy auth v1"))
}

/// Constant-time equality (length leaks; contents do not).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// Lowercase hex encoding.
pub fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// Decode hex (either case); `None` on odd length or a non-hex digit.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let nib = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    b.chunks_exact(2).map(|p| Some(nib(p[0])? << 4 | nib(p[1])?)).collect()
}

/// Decode exactly `N` bytes of hex; `None` on any other length.
pub fn hex_decode_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    hex_decode(s)?.try_into().ok()
}

/// Base64url (RFC 4648 §5) without padding.
pub fn base64url_encode(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        let chars = c.len() + 1;
        for i in 0..chars {
            s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    s
}

/// Lowercase RFC 4648 base32 without padding.
pub fn base32_lower_encode(data: &[u8]) -> String {
    const A: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut s = String::with_capacity((data.len() * 8).div_ceil(5));
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = acc << 8 | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            s.push(A[(acc >> bits & 31) as usize] as char);
        }
    }
    if bits > 0 {
        s.push(A[(acc << (5 - bits) & 31) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings() {
        assert_eq!(hex_encode(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(hex_decode("00ABff"), Some(vec![0, 0xab, 0xff]));
        assert_eq!(hex_decode("0g"), None);
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(base64url_encode(b"f"), "Zg");
        assert_eq!(base64url_encode(b"fo"), "Zm8");
        assert_eq!(base64url_encode(b"foo"), "Zm9v");
        assert_eq!(base64url_encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(base32_lower_encode(b"foobar"), "mzxw6ytboi");
        assert_eq!(base32_lower_encode(&[0u8; 16]).len(), 26);
        assert_eq!(new_token().len(), 43);
    }

    #[test]
    fn uuid_v4() {
        let u = new_uuid_v4();
        assert!(is_uuid(&u), "{u}");
        assert_eq!(&u[14..15], "4");
        assert!(matches!(&u[19..20], "8" | "9" | "a" | "b"));
        assert_ne!(u, new_uuid_v4());
        assert!(!is_uuid("not-a-uuid"));
    }

    #[test]
    fn constant_time_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn hmac_sha256_rfc4231() {
        assert_eq!(
            hex_encode(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Case 6: a key longer than the block size is hashed first.
        assert_eq!(
            hex_encode(&hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First")),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        assert_eq!(proxy_password(&[0; 32]).len(), 64);
    }
}
