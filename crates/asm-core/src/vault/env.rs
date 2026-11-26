//! `.env` file vault (plan step 4). Own parser/writer: rewriting one assignment keeps
//! every other byte of the file unchanged.
//!
//! Assignment line: `^\s*(export\s+)?KEY\s*=\s*VALUE\s*$`, `KEY` = `[A-Za-z_][A-Za-z0-9_]*`.
//! `VALUE` is double-quoted on one line (escapes `\n \r \t \" \\`; only whitespace or a
//! `#` comment may follow), single-quoted on one line (literal), or unquoted (ends at
//! whitespace + `#` or end of line, trimmed). No interpolation. Blank and `#` lines are
//! kept; any other line is kept and ignored ("N lines skipped"). The last duplicate wins.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use super::{AddTarget, SecretKind, SecretMeta, VaultProvider, VaultStatus};
use crate::error::{CoreError, Result};

/// One physical line of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Line {
    /// Line text without its terminator.
    pub text: String,
    /// `"\n"`, `"\r\n"` or `""` (last line without newline).
    pub term: &'static str,
    pub kind: LineKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LineKind {
    Blank,
    Comment,
    /// `value_start..value_end` is the byte range of the raw value token in `text`
    /// (quotes included); it is what a rewrite replaces.
    Assign {
        key: String,
        value: String,
        value_start: usize,
        value_end: usize,
    },
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnvFile {
    pub lines: Vec<Line>,
}

pub(crate) fn is_valid_key(k: &str) -> bool {
    let mut c = k.chars();
    matches!(c.next(), Some(f) if f.is_ascii_alphabetic() || f == '_')
        && c.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

impl EnvFile {
    pub(crate) fn parse(src: &str) -> Self {
        let mut lines = Vec::new();
        let mut rest = src;
        while !rest.is_empty() {
            let (body, term, next) = match rest.find('\n') {
                Some(i) if i > 0 && rest.as_bytes()[i - 1] == b'\r' => {
                    (&rest[..i - 1], "\r\n", &rest[i + 1..])
                }
                Some(i) => (&rest[..i], "\n", &rest[i + 1..]),
                None => (rest, "", ""),
            };
            // A UTF-8 BOM on the first line is kept in `text` but ignored by the parser.
            let offset = if lines.is_empty() && body.starts_with('\u{feff}') {
                '\u{feff}'.len_utf8()
            } else {
                0
            };
            let kind = if offset > 0 {
                parse_text(body)
            } else {
                parse_line(body).unwrap_or(LineKind::Skipped)
            };
            lines.push(Line {
                text: body.to_owned(),
                term,
                kind,
            });
            rest = next;
        }
        EnvFile { lines }
    }

    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        for l in &self.lines {
            out.push_str(&l.text);
            out.push_str(l.term);
        }
        out
    }

    pub(crate) fn skipped(&self) -> usize {
        self.lines
            .iter()
            .filter(|l| l.kind == LineKind::Skipped)
            .count()
    }

    /// Effective key/value pairs (last duplicate wins), in order of each key's last occurrence.
    pub(crate) fn entries(&self) -> Vec<(&str, &str)> {
        let mut out: Vec<(&str, &str)> = Vec::new();
        for l in &self.lines {
            if let LineKind::Assign { key, value, .. } = &l.kind {
                out.retain(|(k, _)| *k != key.as_str());
                out.push((key, value));
            }
        }
        out
    }

    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.lines.iter().rev().find_map(|l| match &l.kind {
            LineKind::Assign { key: k, value, .. } if k == key => Some(value.as_str()),
            _ => None,
        })
    }

    /// Line ending used for new lines: CRLF when the first line ends with CRLF.
    fn newline(&self) -> &'static str {
        match self.lines.first() {
            Some(l) if l.term == "\r\n" => "\r\n",
            _ => "\n",
        }
    }

    /// Rewrite the value of the last assignment of `key`. Returns false when absent.
    pub(crate) fn set(&mut self, key: &str, value: &str) -> bool {
        let Some(line) = self
            .lines
            .iter_mut()
            .rev()
            .find(|l| matches!(&l.kind, LineKind::Assign { key: k, .. } if k == key))
        else {
            return false;
        };
        let LineKind::Assign {
            value_start,
            value_end,
            ..
        } = line.kind
        else {
            unreachable!()
        };
        let encoded = encode_value(value);
        let text = format!(
            "{}{}{}",
            &line.text[..value_start],
            encoded,
            &line.text[value_end..]
        );
        line.kind = parse_text(&text);
        line.text = text;
        true
    }

    /// Append `KEY=value` as a new last line.
    pub(crate) fn append(&mut self, key: &str, value: &str) {
        let nl = self.newline();
        if let Some(last) = self.lines.last_mut()
            && last.term.is_empty()
        {
            last.term = nl;
        }
        let text = format!("{key}={}", encode_value(value));
        let kind = parse_line(&text).unwrap_or(LineKind::Skipped);
        self.lines.push(Line {
            text,
            term: nl,
            kind,
        });
    }
}

fn shift(kind: LineKind, offset: usize) -> LineKind {
    match kind {
        LineKind::Assign {
            key,
            value,
            value_start,
            value_end,
        } => LineKind::Assign {
            key,
            value,
            value_start: value_start + offset,
            value_end: value_end + offset,
        },
        k => k,
    }
}

/// Parse a line that may start with a UTF-8 BOM (only ever the first line of a file).
fn parse_text(text: &str) -> LineKind {
    let offset = if text.starts_with('\u{feff}') {
        '\u{feff}'.len_utf8()
    } else {
        0
    };
    parse_line(&text[offset..]).map_or(LineKind::Skipped, |k| shift(k, offset))
}

fn parse_line(text: &str) -> Option<LineKind> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Some(LineKind::Blank);
    }
    if trimmed.starts_with('#') {
        return Some(LineKind::Comment);
    }
    let b = text.as_bytes();
    let ws = |i: usize| -> usize {
        let mut i = i;
        while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
            i += 1;
        }
        i
    };
    let ident_end = |i: usize| -> usize {
        let mut j = i;
        while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
            j += 1;
        }
        j
    };
    let mut i = ws(0);
    // `export` followed by whitespace and a key; `export=…` is a key named "export".
    if text[i..].starts_with("export") {
        let after = i + "export".len();
        let j = ws(after);
        if j > after && j < b.len() && (b[j].is_ascii_alphabetic() || b[j] == b'_') {
            i = j;
        }
    }
    let key_end = ident_end(i);
    let key = &text[i..key_end];
    if !is_valid_key(key) {
        return None;
    }
    let mut j = ws(key_end);
    if j >= b.len() || b[j] != b'=' {
        return None;
    }
    let eq_end = j + 1;
    j = ws(eq_end);
    // `KEY= #comment`: empty value; a rewrite inserts right after `=`.
    if j > eq_end && b.get(j) == Some(&b'#') {
        return Some(LineKind::Assign {
            key: key.to_owned(),
            value: String::new(),
            value_start: eq_end,
            value_end: eq_end,
        });
    }
    let value_start = j;
    let (value, value_end) = match b.get(j) {
        Some(b'"') => {
            let mut out = String::new();
            let mut k = j + 1;
            let mut chars = text[k..].char_indices();
            let close = loop {
                let (off, c) = chars.next()?;
                match c {
                    '"' => break k + off,
                    '\\' => {
                        let (_, e) = chars.next()?;
                        match e {
                            'n' => out.push('\n'),
                            'r' => out.push('\r'),
                            't' => out.push('\t'),
                            '"' => out.push('"'),
                            '\\' => out.push('\\'),
                            other => {
                                out.push('\\');
                                out.push(other);
                            }
                        }
                    }
                    c => out.push(c),
                }
            };
            k = close + 1;
            if !only_comment(&text[k..]) {
                return None;
            }
            (out, k)
        }
        Some(b'\'') => {
            let close = j + 1 + text[j + 1..].find('\'')?;
            if !only_comment(&text[close + 1..]) {
                return None;
            }
            (text[j + 1..close].to_owned(), close + 1)
        }
        _ => {
            // Unquoted: ends at whitespace followed by `#`, or end of line; trimmed.
            let post = &text[j..];
            let pb = post.as_bytes();
            let mut end = post.len();
            for (p, &c) in pb.iter().enumerate() {
                if c == b'#' && p > 0 && (pb[p - 1] == b' ' || pb[p - 1] == b'\t') {
                    end = p;
                    break;
                }
            }
            let raw = &post[..end];
            let v = raw.trim_end_matches([' ', '\t']);
            (v.to_owned(), j + v.len())
        }
    };
    Some(LineKind::Assign {
        key: key.to_owned(),
        value,
        value_start,
        value_end,
    })
}

/// Only whitespace or whitespace + `#comment` (or nothing) remains.
fn only_comment(rest: &str) -> bool {
    let t = rest.trim_start_matches([' ', '\t']);
    t.is_empty() || t.starts_with('#')
}

/// Unquoted when the value is "simple", else double-quoted with escapes.
pub(crate) fn encode_value(v: &str) -> String {
    let simple = !v.is_empty()
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_./:@%+=,-".contains(&c));
    if simple {
        return v.to_owned();
    }
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp {
    mtime: SystemTime,
    size: u64,
    ino: u64,
}

struct Cache {
    stamp: Stamp,
    file: EnvFile,
}

pub struct EnvFileVault {
    path: PathBuf,
    cache: Mutex<Option<Cache>>,
}

impl EnvFileVault {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            cache: Mutex::new(None),
        }
    }

    fn stamp(&self) -> Result<Stamp> {
        let m = fs::metadata(&self.path).map_err(|e| unavailable(&self.path, e))?;
        if !m.is_file() {
            return Err(CoreError::vault_unavailable(format!(
                "{} is not a regular file",
                self.path.display()
            )));
        }
        Ok(Stamp {
            mtime: m.modified()?,
            size: m.len(),
            ino: m.ino(),
        })
    }

    fn load(&self) -> Result<(Stamp, EnvFile)> {
        let stamp = self.stamp()?;
        let bytes = fs::read(&self.path).map_err(|e| unavailable(&self.path, e))?;
        let src = String::from_utf8(bytes).map_err(|_| {
            CoreError::vault_unavailable(format!("{} is not UTF-8 text", self.path.display()))
        })?;
        Ok((stamp, EnvFile::parse(&src)))
    }

    /// Run `f` on the current file contents, re-reading when mtime, size or inode changed.
    fn with_file<T>(&self, f: impl FnOnce(&EnvFile) -> Result<T>) -> Result<T> {
        let mut guard = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        let stamp = self.stamp();
        let fresh = matches!((&*guard, &stamp), (Some(c), Ok(s)) if c.stamp == *s);
        if !fresh {
            *guard = None;
            let (stamp, file) = self.load()?;
            *guard = Some(Cache { stamp, file });
        }
        f(&guard.as_ref().expect("cache filled").file)
    }

    /// Read-modify-write under the cache lock, always from a fresh read of the file.
    fn modify(&self, f: impl FnOnce(&mut EnvFile) -> Result<()>) -> Result<()> {
        let mut guard = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        *guard = None;
        let (_, mut file) = self.load()?;
        f(&mut file)?;
        write_atomic(&self.path, file.render().as_bytes())?;
        let stamp = self.stamp()?;
        *guard = Some(Cache { stamp, file });
        Ok(())
    }
}

fn unavailable(path: &Path, e: std::io::Error) -> CoreError {
    CoreError::vault_unavailable(format!("{}: {e}", path.display()))
}

/// Write `data` to a temp file in the same directory with the original file's mode, then rename.
fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let meta = fs::metadata(path).map_err(|e| unavailable(path, e))?;
    let mode = meta.permissions().mode() & 0o7777;
    let dir = path
        .parent()
        .ok_or_else(|| CoreError::internal("env file has no parent directory"))?;
    let base = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(
        ".{base}.asm-{}",
        asm_proto::crypto::hex_encode(&asm_proto::crypto::random_bytes::<6>())
    ));
    let res = (|| -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data)?;
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(unavailable(path, e));
    }
    Ok(())
}

impl VaultProvider for EnvFileVault {
    fn status(&self) -> VaultStatus {
        match self.with_file(|_| Ok(())) {
            Ok(()) => VaultStatus::Ready,
            Err(e) => VaultStatus::Error(e.message),
        }
    }

    fn list(&self) -> Result<Vec<SecretMeta>> {
        self.with_file(|f| {
            Ok(f.entries()
                .into_iter()
                .filter(|(_, v)| !v.is_empty())
                .map(|(k, _)| SecretMeta {
                    key: k.to_owned(),
                    name: k.to_owned(),
                    kind: SecretKind::Single,
                    fields: vec!["value".to_owned()],
                    uri_hosts: vec![],
                    collections: vec![],
                })
                .collect())
        })
    }

    fn read(&self, key: &str) -> Result<Vec<(String, String)>> {
        self.with_file(|f| match f.get(key) {
            Some(v) if !v.is_empty() => Ok(vec![("value".to_owned(), v.to_owned())]),
            _ => Err(CoreError::not_found(format!(
                "{key} is not in {}",
                self.path.display()
            ))),
        })
    }

    fn update(&self, key: &str, field: &str, value: &str) -> Result<()> {
        if field != "value" {
            return Err(CoreError::invalid(format!(
                ".env secrets have only the field \"value\", not {field:?}"
            )));
        }
        self.modify(|f| {
            if f.set(key, value) {
                Ok(())
            } else {
                Err(CoreError::not_found(format!(
                    "{key} is not in {}",
                    self.path.display()
                )))
            }
        })
    }

    fn add(&self, name: &str, value: &str, _target: &AddTarget) -> Result<()> {
        if !is_valid_key(name) {
            return Err(CoreError::invalid(format!(
                "{name:?} is not a valid .env key ([A-Za-z_][A-Za-z0-9_]*)"
            )));
        }
        self.modify(|f| {
            f.append(name, value);
            Ok(())
        })
    }

    fn note(&self) -> Option<String> {
        let n = self.with_file(|f| Ok(f.skipped())).ok()?;
        match n {
            0 => None,
            1 => Some("1 line skipped".to_owned()),
            n => Some(format!("{n} lines skipped")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# leading comment\n\
        export API_KEY=abc123 # trailing comment\n\
        \n\
        QUOTED=\"line\\nwith \\\"escapes\\\" \\\\ and \\t tab\"  # c\n\
        SINGLE='lit $x \\n'\n\
        DUP=first\n\
        \t SPACED  =  spaced value  \n\
        not an assignment\n\
        MULTI=\"starts here\n\
        and continues\"\n\
        DUP=second\n\
        EMPTY=\n\
        HASHVAL=a#b\n\
        LAST=end";

    #[test]
    fn parses_values_and_skips() {
        let f = EnvFile::parse(SAMPLE);
        assert_eq!(f.render(), SAMPLE, "render is byte-identical");
        assert_eq!(f.get("API_KEY"), Some("abc123"));
        assert_eq!(
            f.get("QUOTED"),
            Some("line\nwith \"escapes\" \\ and \t tab")
        );
        assert_eq!(f.get("SINGLE"), Some("lit $x \\n"));
        assert_eq!(f.get("DUP"), Some("second"));
        assert_eq!(f.get("SPACED"), Some("spaced value"));
        assert_eq!(f.get("EMPTY"), Some(""));
        assert_eq!(f.get("HASHVAL"), Some("a#b"));
        assert_eq!(f.get("LAST"), Some("end"));
        assert_eq!(f.get("MULTI"), None);
        // "not an assignment", `MULTI="starts here`, `and continues"`
        assert_eq!(f.skipped(), 3);
        let keys: Vec<&str> = f.entries().into_iter().map(|(k, _)| k).collect();
        assert_eq!(
            keys,
            [
                "API_KEY", "QUOTED", "SINGLE", "SPACED", "DUP", "EMPTY", "HASHVAL", "LAST"
            ]
        );
    }

    #[test]
    fn rewrite_keeps_other_lines_byte_identical() {
        let mut f = EnvFile::parse(SAMPLE);
        assert!(f.set("API_KEY", "new value"));
        assert!(f.set("DUP", "third"));
        assert!(f.set("QUOTED", "simple"));
        assert!(f.set("SINGLE", "it's"));
        assert!(!f.set("MISSING", "x"));
        let out = f.render();
        let before: Vec<&str> = SAMPLE.split('\n').collect();
        let after: Vec<&str> = out.split('\n').collect();
        assert_eq!(before.len(), after.len());
        for (i, (b, a)) in before.iter().zip(&after).enumerate() {
            match i {
                1 => assert_eq!(*a, "export API_KEY=\"new value\" # trailing comment"),
                3 => assert_eq!(*a, "QUOTED=simple  # c"),
                4 => assert_eq!(*a, "SINGLE=\"it's\""),
                10 => assert_eq!(*a, "DUP=third"),
                _ => assert_eq!(a, b, "line {i} unchanged"),
            }
        }
        let g = EnvFile::parse(&out);
        assert_eq!(g.get("API_KEY"), Some("new value"));
        assert_eq!(g.get("DUP"), Some("third"));
        assert_eq!(g.get("SINGLE"), Some("it's"));
        assert_eq!(g.lines[5].text, "DUP=first", "earlier duplicate untouched");
    }

    #[test]
    fn crlf_preserved_and_used_for_append() {
        let src = "A=1\r\n# c\r\nB='two'\r\nC=3";
        let mut f = EnvFile::parse(src);
        assert_eq!(f.render(), src);
        assert_eq!(f.get("B"), Some("two"));
        assert!(f.set("B", "x y"));
        f.append("NEW_KEY", "tab\there");
        assert_eq!(
            f.render(),
            "A=1\r\n# c\r\nB=\"x y\"\r\nC=3\r\nNEW_KEY=\"tab\\there\"\r\n"
        );
        let g = EnvFile::parse(&f.render());
        assert_eq!(g.get("NEW_KEY"), Some("tab\there"));
        assert_eq!(g.get("C"), Some("3"));
    }

    #[test]
    fn encode_round_trips() {
        for v in [
            "plain",
            "a b",
            "q\"uote",
            "back\\slash",
            "multi\nline\r\n",
            "#hash",
            "x=y,z:@%+-./",
            "é ü",
            "$HOME",
        ] {
            let line = format!("K={}", encode_value(v));
            let f = EnvFile::parse(&line);
            assert_eq!(f.get("K"), Some(v), "value {v:?} via {line:?}");
        }
        assert_eq!(encode_value("x=y,z:@%+-./"), "x=y,z:@%+-./");
        assert_eq!(encode_value("a b"), "\"a b\"");
    }

    #[test]
    fn export_edge_cases() {
        let f = EnvFile::parse("export=1\nexport  FOO=bar\nexportX=2\nexport\n");
        assert_eq!(f.get("export"), Some("1"));
        assert_eq!(f.get("FOO"), Some("bar"));
        assert_eq!(f.get("exportX"), Some("2"));
        assert_eq!(f.skipped(), 1);
    }

    #[test]
    fn empty_value_with_comment_and_bom() {
        let mut f = EnvFile::parse("\u{feff}FIRST=1\nKEY= # note\n");
        assert_eq!(f.get("FIRST"), Some("1"));
        assert_eq!(f.get("KEY"), Some(""));
        assert!(f.set("KEY", "v"));
        assert!(f.set("FIRST", "2"));
        assert_eq!(f.render(), "\u{feff}FIRST=2\nKEY=v # note\n");
        assert_eq!(EnvFile::parse(&f.render()).get("KEY"), Some("v"));
    }

    #[test]
    fn junk_after_quotes_is_skipped() {
        let f = EnvFile::parse("A=\"x\" y\nB='x'z\nC=\"x\"#c\nD=\"x\" #c\n");
        assert_eq!(f.get("A"), None);
        assert_eq!(f.get("B"), None);
        assert_eq!(f.get("C"), Some("x"));
        assert_eq!(f.get("D"), Some("x"));
        assert_eq!(f.skipped(), 2);
    }

    #[test]
    fn provider_update_add_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        let src = "# keep\r\nexport DEMO_TOKEN=real-value-123\r\nOTHER='x'\r\nbroken line\r\n";
        fs::write(&path, src).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let v = EnvFileVault::new(path.clone());
        assert_eq!(v.status(), VaultStatus::Ready);
        assert_eq!(v.note().as_deref(), Some("1 line skipped"));
        let names: Vec<String> = v.list().unwrap().into_iter().map(|m| m.name).collect();
        assert_eq!(names, ["DEMO_TOKEN", "OTHER"]);
        assert_eq!(
            v.read("DEMO_TOKEN").unwrap(),
            [("value".to_owned(), "real-value-123".to_owned())]
        );

        v.update("DEMO_TOKEN", "value", "real-value-456").unwrap();
        v.add("NEW_ONE", "with space", &AddTarget::default())
            .unwrap();
        let out = fs::read_to_string(&path).unwrap();
        assert_eq!(
            out,
            "# keep\r\nexport DEMO_TOKEN=real-value-456\r\nOTHER='x'\r\nbroken line\r\nNEW_ONE=\"with space\"\r\n"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no temp files left"
        );

        assert_eq!(
            v.update("DEMO_TOKEN", "password", "x").unwrap_err().code,
            asm_proto::ErrorCode::Invalid
        );
        assert_eq!(
            v.update("MISSING", "value", "x").unwrap_err().code,
            asm_proto::ErrorCode::NotFound
        );
        assert_eq!(
            v.add("bad-name", "x", &AddTarget::default())
                .unwrap_err()
                .code,
            asm_proto::ErrorCode::Invalid
        );

        // External edit (size change) is picked up.
        fs::write(&path, "DEMO_TOKEN=changed-outside\n").unwrap();
        assert_eq!(v.read("DEMO_TOKEN").unwrap()[0].1, "changed-outside");
        assert_eq!(v.note(), None);

        fs::remove_file(&path).unwrap();
        assert!(matches!(v.status(), VaultStatus::Error(_)));
        assert_eq!(
            v.list().unwrap_err().code,
            asm_proto::ErrorCode::VaultUnavailable
        );
    }
}
