//! Log-line redaction of active real values (plan step 6).
//!
//! Forms replaced: raw, Go `url.QueryEscape`, Go `url.PathEscape`, and the JSON string
//! escape (iron-proxy logs are JSON lines, so a value with `"` or `\` appears escaped).

pub const REDACTED: &str = "asm_redacted";

#[derive(Debug, Default, Clone)]
pub struct Redactor {
    /// Longest first, de-duplicated, never empty strings.
    needles: Vec<String>,
}

impl Redactor {
    pub fn new<S: AsRef<str>>(values: &[S]) -> Self {
        let mut needles: Vec<String> = Vec::with_capacity(values.len() * 4);
        for v in values {
            let v = v.as_ref();
            if v.is_empty() {
                continue;
            }
            let json = serde_json::to_string(v).expect("string serialisation cannot fail");
            for form in [
                v.to_string(),
                query_escape(v),
                path_escape(v),
                json[1..json.len() - 1].to_string(),
            ] {
                if !needles.contains(&form) {
                    needles.push(form);
                }
            }
        }
        needles.sort_by(|a, b| b.len().cmp(&a.len()));
        Self { needles }
    }

    pub fn is_empty(&self) -> bool {
        self.needles.is_empty()
    }

    /// Replace every occurrence of any needle (longest match wins at each position).
    pub fn redact(&self, line: &str) -> String {
        if self.needles.is_empty() {
            return line.to_string();
        }
        let bytes = line.as_bytes();
        let mut out = String::with_capacity(line.len());
        let mut copied = 0;
        let mut i = 0;
        while i < bytes.len() {
            match self
                .needles
                .iter()
                .find(|n| bytes[i..].starts_with(n.as_bytes()))
            {
                Some(n) => {
                    // Needles are whole UTF-8 strings, so `i` and `i + len` are char boundaries.
                    out.push_str(&line[copied..i]);
                    out.push_str(REDACTED);
                    i += n.len();
                    copied = i;
                }
                None => i += 1,
            }
        }
        out.push_str(&line[copied..]);
        out
    }
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

fn push_pct(out: &mut String, b: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.push('%');
    out.push(HEX[(b >> 4) as usize] as char);
    out.push(HEX[(b & 15) as usize] as char);
}

/// Go `url.QueryEscape`: space → `+`, unreserved kept, everything else `%XX`.
pub fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for &b in s.as_bytes() {
        if is_unreserved(b) {
            out.push(b as char);
        } else if b == b' ' {
            out.push('+');
        } else {
            push_pct(&mut out, b);
        }
    }
    out
}

/// Go `url.PathEscape` (encodePathSegment): unreserved and `$&+,:;=@` kept, rest `%XX`.
pub fn path_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for &b in s.as_bytes() {
        if is_unreserved(b) || matches!(b, b'$' | b'&' | b'+' | b',' | b':' | b';' | b'=' | b'@') {
            out.push(b as char);
        } else {
            push_pct(&mut out, b);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_escapes() {
        assert_eq!(
            query_escape("a b/c?d=e&f+g~ü"),
            "a+b%2Fc%3Fd%3De%26f%2Bg~%C3%BC"
        );
        assert_eq!(path_escape("a b/c?d=e&f+g~ü"), "a%20b%2Fc%3Fd=e&f+g~%C3%BC");
    }

    #[test]
    fn redacts_raw_escaped_and_json_forms() {
        let r = Redactor::new(&["real value/1", "q\"x\\y"]);
        let line = r#"{"msg":"real value/1","url":"https://h/p?k=real+value%2F1&p=/real%20value%2F1","x":"q\"x\\y"}"#;
        let out = r.redact(line);
        assert!(!out.contains("real"), "{out}");
        assert!(!out.contains("q\\\"x"), "{out}");
        assert_eq!(out.matches(REDACTED).count(), 4, "{out}");
    }

    #[test]
    fn longest_match_wins_and_multibyte_safe() {
        let r = Redactor::new(&["abc", "abcdef"]);
        assert_eq!(
            r.redact("xxabcdefyy abc é"),
            "xxasm_redactedyy asm_redacted é"
        );
        assert_eq!(Redactor::new::<&str>(&[]).redact("é abc"), "é abc");
        assert_eq!(Redactor::new(&["é"]).redact("aéb"), "aasm_redactedb");
    }

    #[test]
    fn empty_values_ignored() {
        let r = Redactor::new(&[""]);
        assert!(r.is_empty());
        assert_eq!(r.redact("line"), "line");
    }
}
