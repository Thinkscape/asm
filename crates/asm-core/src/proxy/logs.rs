//! iron-proxy log capture: redacted lines go to a ring buffer and `<logs>/proxy.log`
//! (rotated at 10 MB, one old file kept as `proxy.log.1`).

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::redact::Redactor;

pub const RING_LINES: usize = 2000;
pub const ROTATE_BYTES: u64 = 10 * 1024 * 1024;

pub struct LogSink {
    inner: Mutex<Inner>,
}

struct Inner {
    ring: VecDeque<String>,
    capacity: usize,
    path: PathBuf,
    rotate_bytes: u64,
    file: Option<File>,
    size: u64,
    redactor: Redactor,
}

impl LogSink {
    pub fn new(path: PathBuf) -> Self {
        Self::with_limits(path, RING_LINES, ROTATE_BYTES)
    }

    pub fn with_limits(path: PathBuf, capacity: usize, rotate_bytes: u64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                ring: VecDeque::with_capacity(capacity.min(RING_LINES)),
                capacity,
                path,
                rotate_bytes,
                file: None,
                size: 0,
                redactor: Redactor::default(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_redactor(&self, r: Redactor) {
        self.lock().redactor = r;
    }

    /// Redact, then store one line (trailing newline characters are stripped).
    pub fn push(&self, line: &str) {
        self.push_inspect(line, |_| ());
    }

    /// As [`push`](Self::push), handing the redacted line to `inspect` first.
    pub fn push_inspect<R>(&self, line: &str, inspect: impl FnOnce(&str) -> R) -> R {
        let line = line.trim_end_matches(['\n', '\r']);
        let mut g = self.lock();
        let line = g.redactor.redact(line);
        let out = inspect(&line);
        g.write_file(&line);
        if g.ring.len() == g.capacity {
            g.ring.pop_front();
        }
        g.ring.push_back(line);
        out
    }

    /// The last `n` lines, oldest first.
    pub fn tail(&self, n: usize) -> Vec<String> {
        let g = self.lock();
        let skip = g.ring.len().saturating_sub(n);
        g.ring.iter().skip(skip).cloned().collect()
    }

    pub fn last(&self) -> Option<String> {
        self.lock().ring.back().cloned()
    }
}

impl Inner {
    fn write_file(&mut self, line: &str) {
        let len = line.len() as u64 + 1;
        if self.file.is_none() {
            self.file = open_log(&self.path);
            self.size = self
                .file
                .as_ref()
                .and_then(|f| f.metadata().ok())
                .map_or(0, |m| m.len());
        }
        if self.size > 0 && self.size + len > self.rotate_bytes {
            self.file = None;
            let _ = std::fs::rename(&self.path, rotated_path(&self.path));
            self.file = open_log(&self.path);
            self.size = 0;
        }
        if let Some(f) = self.file.as_mut() {
            let mut buf = Vec::with_capacity(line.len() + 1);
            buf.extend_from_slice(line.as_bytes());
            buf.push(b'\n');
            if f.write_all(&buf).is_ok() {
                self.size += len;
            } else {
                // Reopen on the next line (e.g. the file was removed underneath us).
                self.file = None;
            }
        }
    }
}

fn open_log(path: &Path) -> Option<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .ok()
}

pub fn rotated_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".1");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_keeps_last_lines_and_redacts() {
        let dir = tempfile::tempdir().unwrap();
        let sink = LogSink::with_limits(dir.path().join("proxy.log"), 3, ROTATE_BYTES);
        sink.set_redactor(Redactor::new(&["s3cr3t-value"]));
        for i in 0..5 {
            sink.push(&format!("line {i} s3cr3t-value\n"));
        }
        assert_eq!(
            sink.tail(10),
            vec![
                "line 2 asm_redacted",
                "line 3 asm_redacted",
                "line 4 asm_redacted"
            ]
        );
        assert_eq!(sink.tail(1), vec!["line 4 asm_redacted"]);
        let file = std::fs::read_to_string(dir.path().join("proxy.log")).unwrap();
        assert_eq!(file.lines().count(), 5);
        assert!(!file.contains("s3cr3t"));
    }

    #[test]
    fn rotates_and_keeps_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.log");
        let sink = LogSink::with_limits(path.clone(), 100, 26);
        for i in 0..7 {
            sink.push(&format!("0123456789-{i}"));
        }
        // 13 bytes per line incl. newline: two lines fit per file.
        let cur = std::fs::read_to_string(&path).unwrap();
        let old = std::fs::read_to_string(rotated_path(&path)).unwrap();
        assert_eq!(cur, "0123456789-6\n");
        assert_eq!(old, "0123456789-4\n0123456789-5\n");
        assert!(!dir.path().join("proxy.log.2").exists());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
