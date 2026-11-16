//! Shared validation rules: host patterns, agent text, reasons, secret values,
//! sentinels, path segments and lease file paths.

use crate::crypto::random_bytes;
use crate::error::ApiError;
use crate::wire::SecretKind;
use std::io::Read;

/// Maximum length of a reason, in Unicode scalar values.
pub const MAX_REASON_CHARS: usize = 250;
/// Maximum size of a secret value, in bytes.
pub const MAX_SECRET_VALUE_BYTES: usize = 65_536;
/// Prefix of every sentinel.
pub const SENTINEL_PREFIX: &str = "asm_";
/// Number of base62 characters after [`SENTINEL_PREFIX`].
pub const SENTINEL_RANDOM_CHARS: usize = 40;

// ---------------------------------------------------------------------------
// Host patterns
// ---------------------------------------------------------------------------

/// Validate and normalise one host pattern (iron-proxy `rules[].host` syntax):
/// trimmed, lowercased, ASCII only; rejects empty patterns, whitespace, control
/// characters, `/`, `:` and malformed globs.
pub fn normalize_host_pattern(pattern: &str) -> Result<String, ApiError> {
    let p = pattern.trim();
    if p.is_empty() {
        return Err(ApiError::invalid("host pattern is empty"));
    }
    if !p.is_ascii() {
        return Err(ApiError::invalid(format!("host pattern {p:?} is not ASCII")));
    }
    if let Some(c) = p.chars().find(|c| c.is_ascii_whitespace() || c.is_ascii_control() || *c == '/' || *c == ':') {
        return Err(ApiError::invalid(format!("host pattern {p:?} contains {c:?}; give a hostname without scheme, port or path")));
    }
    let p = p.to_ascii_lowercase();
    if !glob_is_valid(&p) {
        return Err(ApiError::invalid(format!("host pattern {p:?} is a malformed glob")));
    }
    Ok(p)
}

/// Normalise a list of host patterns, then sort and de-duplicate it.
pub fn normalize_host_patterns<S: AsRef<str>>(patterns: &[S]) -> Result<Vec<String>, ApiError> {
    let mut out = patterns.iter().map(|p| normalize_host_pattern(p.as_ref())).collect::<Result<Vec<_>, _>>()?;
    out.sort();
    out.dedup();
    Ok(out)
}

/// iron-proxy host matching (`hostmatch.MatchGlob`): case-insensitive; `*` matches
/// any host; `*.example.com` matches `example.com` and every subdomain; otherwise a
/// Go `path.Match` glob (its `*` also matches dots). Malformed patterns match nothing.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let host = host.to_lowercase();
    if pattern == "*" {
        return true;
    }
    if let Some(rest) = pattern.strip_prefix("*.") {
        return host.ends_with(&pattern[1..]) || host == rest;
    }
    glob_match(&pattern, &host).unwrap_or(false)
}

/// True when any pattern matches `host`.
pub fn host_matches_any<S: AsRef<str>>(patterns: &[S], host: &str) -> bool {
    patterns.iter().any(|p| host_matches(p.as_ref(), host))
}

/// A pattern is broad when it is neither a literal hostname/IP nor
/// `*.<two or more labels>` (with a literal remainder). Broad patterns are
/// allowed but flagged to the operator.
pub fn is_broad(pattern: &str) -> bool {
    let has_meta = |s: &str| s.contains(['*', '?', '[', ']', '\\']);
    if !has_meta(pattern) {
        return false;
    }
    match pattern.strip_prefix("*.") {
        Some(rest) if !has_meta(rest) => {
            let labels: Vec<&str> = rest.split('.').collect();
            !(labels.len() >= 2 && labels.iter().all(|l| !l.is_empty()))
        }
        _ => true,
    }
}

/// Go `path.Match` on `name`; `None` for a malformed pattern (`ErrBadPattern`).
pub fn glob_match(pattern: &str, name: &str) -> Option<bool> {
    path_match(pattern.as_bytes(), name.as_bytes()).ok()
}

fn path_match(mut pattern: &[u8], mut name: &[u8]) -> Result<bool, ()> {
    'pattern: while !pattern.is_empty() {
        let (star, chunk, rest) = scan_chunk(pattern);
        pattern = rest;
        if star && chunk.is_empty() {
            return Ok(!name.contains(&b'/'));
        }
        let (t, ok) = match_chunk(chunk, name)?;
        if ok && (t.is_empty() || !pattern.is_empty()) {
            name = t;
            continue;
        }
        if star {
            let mut i = 0;
            while i < name.len() && name[i] != b'/' {
                let (t, ok) = match_chunk(chunk, &name[i + 1..])?;
                if ok {
                    if pattern.is_empty() && !t.is_empty() {
                        i += 1;
                        continue;
                    }
                    name = t;
                    continue 'pattern;
                }
                i += 1;
            }
        }
        // Report a malformed remainder even when the match already failed.
        while !pattern.is_empty() {
            let (_, chunk, rest) = scan_chunk(pattern);
            pattern = rest;
            match_chunk(chunk, b"")?;
        }
        return Ok(false);
    }
    Ok(name.is_empty())
}

/// True when the whole pattern is a well-formed `path.Match` glob.
pub fn glob_is_valid(pattern: &str) -> bool {
    let mut p = pattern.as_bytes();
    while !p.is_empty() {
        let (_, chunk, rest) = scan_chunk(p);
        p = rest;
        if match_chunk(chunk, b"").is_err() {
            return false;
        }
    }
    true
}

fn scan_chunk(mut pattern: &[u8]) -> (bool, &[u8], &[u8]) {
    let mut star = false;
    while let [b'*', rest @ ..] = pattern {
        pattern = rest;
        star = true;
    }
    let mut in_range = false;
    let mut i = 0;
    while i < pattern.len() {
        match pattern[i] {
            b'\\' => {
                if i + 1 < pattern.len() {
                    i += 1;
                }
            }
            b'[' => in_range = true,
            b']' => in_range = false,
            b'*' if !in_range => break,
            _ => {}
        }
        i += 1;
    }
    (star, &pattern[..i], &pattern[i..])
}

/// Decode one UTF-8 scalar; invalid input yields U+FFFD and width 1 (like Go).
fn decode_char(s: &[u8]) -> (u32, usize) {
    let w = match s[0] {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => return (0xfffd, 1),
    };
    match s.get(..w).and_then(|b| std::str::from_utf8(b).ok()) {
        Some(c) => (c.chars().next().unwrap() as u32, w),
        None => (0xfffd, 1),
    }
}

fn match_chunk<'a>(mut chunk: &[u8], mut s: &'a [u8]) -> Result<(&'a [u8], bool), ()> {
    let mut failed = false;
    while !chunk.is_empty() {
        if !failed && s.is_empty() {
            failed = true;
        }
        match chunk[0] {
            b'[' => {
                let mut r = 0u32;
                if !failed {
                    let (c, n) = decode_char(s);
                    r = c;
                    s = &s[n..];
                }
                chunk = &chunk[1..];
                let negated = chunk.first() == Some(&b'^');
                if negated {
                    chunk = &chunk[1..];
                }
                let mut matched = false;
                let mut nrange = 0;
                loop {
                    if chunk.first() == Some(&b']') && nrange > 0 {
                        chunk = &chunk[1..];
                        break;
                    }
                    let (lo, rest) = get_esc(chunk)?;
                    chunk = rest;
                    let mut hi = lo;
                    if chunk[0] == b'-' {
                        let (h, rest) = get_esc(&chunk[1..])?;
                        hi = h;
                        chunk = rest;
                    }
                    if lo <= r && r <= hi {
                        matched = true;
                    }
                    nrange += 1;
                }
                if matched == negated {
                    failed = true;
                }
            }
            b'?' => {
                if !failed {
                    if s[0] == b'/' {
                        failed = true;
                    }
                    let (_, n) = decode_char(s);
                    s = &s[n..];
                }
                chunk = &chunk[1..];
            }
            c => {
                let c = if c == b'\\' {
                    chunk = &chunk[1..];
                    *chunk.first().ok_or(())?
                } else {
                    c
                };
                if !failed {
                    if c != s[0] {
                        failed = true;
                    }
                    s = &s[1..];
                }
                chunk = &chunk[1..];
            }
        }
    }
    Ok(if failed { (&[][..], false) } else { (s, true) })
}

fn get_esc(mut chunk: &[u8]) -> Result<(u32, &[u8]), ()> {
    if chunk.is_empty() || chunk[0] == b'-' || chunk[0] == b']' {
        return Err(());
    }
    if chunk[0] == b'\\' {
        chunk = &chunk[1..];
        if chunk.is_empty() {
            return Err(());
        }
    }
    let (r, n) = decode_char(chunk);
    if r == 0xfffd && n == 1 && chunk[0] >= 0x80 {
        return Err(());
    }
    let rest = &chunk[n..];
    if rest.is_empty() {
        return Err(());
    }
    Ok((r, rest))
}

// ---------------------------------------------------------------------------
// Agent text, reasons, secret values
// ---------------------------------------------------------------------------

/// True for bidi embedding/override/isolate controls (U+202A–202E, U+2066–2069).
pub fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Validate text supplied by an agent (reason, agent label, host-info strings):
/// rejects control characters and bidi controls with `invalid`. `what` names the
/// field in the error message.
pub fn validate_agent_text(what: &str, text: &str) -> Result<(), ApiError> {
    if let Some(c) = text.chars().find(|c| c.is_control() || is_bidi_control(*c)) {
        return Err(ApiError::invalid(format!("{what} contains the forbidden character U+{:04X}", c as u32)));
    }
    Ok(())
}

/// Validate a reason: trimmed, 1–250 Unicode scalar values, no control or bidi
/// characters. Returns the trimmed reason.
pub fn validate_reason(reason: &str) -> Result<String, ApiError> {
    let r = reason.trim();
    validate_agent_text("reason", r)?;
    let n = r.chars().count();
    if n == 0 {
        return Err(ApiError::invalid("reason is required"));
    }
    if n > MAX_REASON_CHARS {
        return Err(ApiError::invalid(format!("reason has {n} characters; at most {MAX_REASON_CHARS} are allowed")));
    }
    Ok(r.to_owned())
}

/// Check a secret value: non-empty and at most 65,536 bytes.
pub fn validate_secret_value(value: &str) -> Result<(), ApiError> {
    if value.is_empty() {
        return Err(ApiError::invalid("secret value is empty"));
    }
    if value.len() > MAX_SECRET_VALUE_BYTES {
        return Err(ApiError::invalid(format!("secret value exceeds {MAX_SECRET_VALUE_BYTES} bytes")));
    }
    Ok(())
}

/// Read a secret value from stdin-like input: read to EOF, strip one trailing
/// `\n` (and a `\r` before it); must be non-empty UTF-8 of at most 65,536 bytes.
pub fn read_secret_value(input: impl Read) -> Result<String, ApiError> {
    let mut buf = Vec::new();
    // Two extra bytes for the stripped line ending, one more to detect overflow.
    input
        .take(MAX_SECRET_VALUE_BYTES as u64 + 3)
        .read_to_end(&mut buf)
        .map_err(|e| ApiError::invalid(format!("reading secret value: {e}")))?;
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    }
    if buf.len() > MAX_SECRET_VALUE_BYTES {
        return Err(ApiError::invalid(format!("secret value exceeds {MAX_SECRET_VALUE_BYTES} bytes")));
    }
    let s = String::from_utf8(buf).map_err(|_| ApiError::invalid("secret value is not UTF-8 text"))?;
    validate_secret_value(&s)?;
    Ok(s)
}

// ---------------------------------------------------------------------------
// Sentinels
// ---------------------------------------------------------------------------

/// A new sentinel: `asm_` + 40 random base62 characters (unbiased, OS CSPRNG).
pub fn new_sentinel() -> String {
    const B62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut s = String::with_capacity(SENTINEL_PREFIX.len() + SENTINEL_RANDOM_CHARS);
    s.push_str(SENTINEL_PREFIX);
    let mut n = 0;
    while n < SENTINEL_RANDOM_CHARS {
        for b in random_bytes::<64>() {
            // 248 = 4 * 62: reject the tail to keep the distribution uniform.
            if b < 248 && n < SENTINEL_RANDOM_CHARS {
                s.push(B62[(b % 62) as usize] as char);
                n += 1;
            }
        }
    }
    s
}

/// True when `s` has the exact sentinel shape `asm_[0-9A-Za-z]{40}`.
pub fn is_sentinel(s: &str) -> bool {
    s.strip_prefix(SENTINEL_PREFIX)
        .is_some_and(|r| r.len() == SENTINEL_RANDOM_CHARS && r.bytes().all(|b| b.is_ascii_alphanumeric()))
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// Sanitise one path segment: every character outside `[A-Za-z0-9._-]` becomes
/// `_`; a segment that is empty, `.` or `..` becomes `_`.
pub fn sanitize_segment(segment: &str) -> String {
    let s: String = segment
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' })
        .collect();
    if s.is_empty() || s == "." || s == ".." { "_".to_owned() } else { s }
}

/// Relative file paths of a lease, one per field in `fields` order:
/// `[<vault>/]<name>[.<field>]` with sanitised segments. Pass `vault` only while
/// names are vault-prefixed; the field suffix is used for kinds `Login` and
/// `Multi`. Paths that collide get `~2`, `~3`, … in field order.
pub fn relative_paths<S: AsRef<str>>(vault: Option<&str>, name: &str, kind: SecretKind, fields: &[S]) -> Vec<String> {
    let prefix = vault.map(|v| format!("{}/", sanitize_segment(v))).unwrap_or_default();
    let with_field = matches!(kind, SecretKind::Login | SecretKind::Multi);
    let mut out: Vec<String> = Vec::with_capacity(fields.len());
    for f in fields {
        let file = if with_field {
            sanitize_segment(&format!("{name}.{}", f.as_ref()))
        } else {
            sanitize_segment(name)
        };
        let base = format!("{prefix}{file}");
        let mut path = base.clone();
        let mut n = 2;
        while out.contains(&path) {
            path = format!("{base}~{n}");
            n += 1;
        }
        out.push(path);
    }
    out
}

/// Check a `relative_path` received from the manager before writing it: not
/// absolute, at most two segments, no empty, `.` or `..` segment, no `\` or NUL.
/// Returns the segments.
pub fn check_relative_path(path: &str) -> Result<Vec<&str>, ApiError> {
    let bad = |why: &str| Err(ApiError::invalid(format!("unsafe relative path {path:?}: {why}")));
    if path.is_empty() {
        return bad("empty");
    }
    if path.starts_with('/') {
        return bad("absolute");
    }
    if path.contains(['\\', '\0']) {
        return bad("contains a backslash or NUL");
    }
    let segs: Vec<&str> = path.split('/').collect();
    if segs.len() > 2 {
        return bad("more than two segments");
    }
    if segs.iter().any(|s| s.is_empty() || *s == "." || *s == "..") {
        return bad("empty, '.' or '..' segment");
    }
    Ok(segs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_pattern_matching() {
        assert!(host_matches("*.example.com", "example.com"));
        assert!(host_matches("*.example.com", "a.b.example.com"));
        assert!(host_matches("*.Example.COM", "API.example.com"));
        assert!(!host_matches("*.example.com", "badexample.com"));
        assert!(host_matches("*", "anything.at.all"));
        assert!(host_matches("api.github.com", "API.GitHub.com"));
        assert!(!host_matches("api.github.com", "api.github.com.evil"));
        // path.Match: `*` crosses dots, `?`, classes, escapes.
        assert!(host_matches("*github.com", "api.github.com"));
        assert!(host_matches("*github.com", "evilgithub.com"));
        assert!(host_matches("api-?.x.io", "api-1.x.io"));
        assert!(!host_matches("api-?.x.io", "api-12.x.io"));
        assert!(host_matches("api-[0-9].x.io", "api-7.x.io"));
        assert!(!host_matches("api-[^0-9].x.io", "api-7.x.io"));
        assert!(host_matches("a\\*b", "a*b"));
        assert!(!host_matches("a\\*b", "axb"));
        assert!(host_matches("a*b*c", "a.x.b.y.c"));
        assert!(!host_matches("[a-", "a"));
        assert!(host_matches("10.0.0.1", "10.0.0.1"));
    }

    #[test]
    fn host_pattern_validation() {
        assert_eq!(normalize_host_pattern("  API.Example.com ").unwrap(), "api.example.com");
        assert!(normalize_host_pattern("bücher.de").is_err());
        assert!(normalize_host_pattern("").is_err());
        assert!(normalize_host_pattern("a b").is_err());
        assert!(normalize_host_pattern("https://x.com").is_err());
        assert!(normalize_host_pattern("x.com:443").is_err());
        assert!(normalize_host_pattern("x.com/path").is_err());
        assert!(normalize_host_pattern("[a-").is_err());
        assert!(normalize_host_pattern("a\\").is_err());
        assert_eq!(normalize_host_patterns(&["b.com", "A.com", "a.com"]).unwrap(), vec!["a.com", "b.com"]);
    }

    #[test]
    fn broad_patterns() {
        assert!(is_broad("*github.com"));
        assert!(is_broad("*"));
        assert!(is_broad("*.com"));
        assert!(is_broad("api-?.x.io"));
        assert!(is_broad("*.*.example.com"));
        assert!(!is_broad("api.github.com"));
        assert!(!is_broad("127.0.0.1"));
        assert!(!is_broad("*.example.com"));
        assert!(!is_broad("*.a.example.com"));
    }

    #[test]
    fn reasons() {
        assert_eq!(validate_reason("  deploy  ").unwrap(), "deploy");
        assert!(validate_reason(&"é".repeat(250)).is_ok());
        assert!(validate_reason(&"é".repeat(251)).is_err());
        assert!(validate_reason("   ").is_err());
        assert!(validate_reason("abc\u{202E}def").is_err());
        assert!(validate_reason("abc\u{2066}def").is_err());
        assert!(validate_reason("line\nbreak").is_err());
        assert!(validate_agent_text("agent", "claude\u{7}").is_err());
        assert!(validate_agent_text("agent", "claude-code").is_ok());
    }

    #[test]
    fn secret_values() {
        let r = |b: &[u8]| read_secret_value(b);
        assert_eq!(r(b"abc\n").unwrap(), "abc");
        assert_eq!(r(b"abc\r\n").unwrap(), "abc");
        assert_eq!(r(b"abc\n\n").unwrap(), "abc\n");
        assert_eq!(r(b"abc\r").unwrap(), "abc\r");
        assert_eq!(r(b"a\nb").unwrap(), "a\nb");
        assert!(r(b"\n").is_err());
        assert!(r(b"").is_err());
        assert!(r(&[0xff, 0xfe]).is_err());
        let mut max = vec![b'x'; MAX_SECRET_VALUE_BYTES];
        assert!(r(&max).is_ok());
        max.extend_from_slice(b"\r\n");
        assert_eq!(r(&max).unwrap().len(), MAX_SECRET_VALUE_BYTES);
        assert!(r(&vec![b'x'; MAX_SECRET_VALUE_BYTES + 1]).is_err());
    }

    #[test]
    fn sentinels() {
        let s = new_sentinel();
        assert!(is_sentinel(&s), "{s}");
        assert_eq!(s.len(), 44);
        assert_ne!(s, new_sentinel());
        assert!(!is_sentinel("asm_short"));
    }

    #[test]
    fn segments() {
        assert_eq!(sanitize_segment("otp seed"), "otp_seed");
        assert_eq!(sanitize_segment(".."), "_");
        assert_eq!(sanitize_segment("."), "_");
        assert_eq!(sanitize_segment(""), "_");
        assert_eq!(sanitize_segment("a/b~c"), "a_b_c");
        assert_eq!(sanitize_segment("ünï"), "_n_");
    }

    #[test]
    fn lease_paths() {
        assert_eq!(relative_paths(None, "DEMO_TOKEN", SecretKind::Single, &["value"]), vec!["DEMO_TOKEN"]);
        let f = ["username", "password", "otp seed"];
        assert_eq!(
            relative_paths(None, "GitHub", SecretKind::Login, &f),
            vec!["GitHub.username", "GitHub.password", "GitHub.otp_seed"]
        );
        assert_eq!(
            relative_paths(Some("work"), "GitHub", SecretKind::Login, &f),
            vec!["work/GitHub.username", "work/GitHub.password", "work/GitHub.otp_seed"]
        );
        assert_eq!(
            relative_paths(None, "n", SecretKind::Multi, &["a b", "a_b", "a/b"]),
            vec!["n.a_b", "n.a_b~2", "n.a_b~3"]
        );
        assert_eq!(relative_paths(Some("my vault"), "..", SecretKind::Single, &["value"]), vec!["my_vault/_"]);
    }

    #[test]
    fn relative_path_checks() {
        assert_eq!(check_relative_path("work/GitHub.password").unwrap(), vec!["work", "GitHub.password"]);
        assert!(check_relative_path("DEMO").is_ok());
        assert!(check_relative_path("../x").is_err());
        assert!(check_relative_path("a/..").is_err());
        assert!(check_relative_path("/etc/passwd").is_err());
        assert!(check_relative_path("a/b/c").is_err());
        assert!(check_relative_path("a//b").is_err());
        assert!(check_relative_path("").is_err());
    }
}
