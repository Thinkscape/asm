//! Chrome DevTools Protocol over `--remote-debugging-pipe`: Chrome reads commands from
//! its fd 3 and writes replies and events to its fd 4, each message one JSON text
//! terminated by `\0`. A reader thread routes replies to their callers by `id` and
//! queues events. Messages are never logged: fill calls carry the password.

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use crate::manager::lock;
use zeroize::Zeroizing;

/// Events kept for [`Cdp::drain_events`]; older ones are dropped.
const MAX_EVENTS: usize = 256;

/// Why a call returned no result. Never carries the call's parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CdpError {
    /// No reply within the call's timeout.
    Timeout(String),
    /// The pipe closed (Chrome exited).
    Closed,
    /// Chrome answered with an error.
    Protocol(String),
}

impl std::error::Error for CdpError {}

impl std::fmt::Display for CdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout(method) => write!(f, "{method} timed out"),
            Self::Closed => f.write_str("the browser closed the debugging pipe"),
            Self::Protocol(message) => f.write_str(message),
        }
    }
}

/// An event: `method`, `params` and the session it came from (`None` = the browser).
#[derive(Debug, Clone)]
pub(crate) struct Event {
    pub method: String,
    pub params: Value,
    pub session: Option<String>,
}

type Reply = Result<Value, String>;

#[derive(Default)]
struct Shared {
    pending: Mutex<HashMap<u64, mpsc::Sender<Reply>>>,
    events: Mutex<VecDeque<Event>>,
    closed: AtomicBool,
}

pub(crate) struct Cdp {
    writer: Mutex<Box<dyn Write + Send>>,
    next_id: AtomicU64,
    shared: Arc<Shared>,
}

impl Cdp {
    /// Talk to Chrome over `to_chrome` (its fd 3) and `from_chrome` (its fd 4).
    pub(crate) fn new(
        to_chrome: impl Write + Send + 'static,
        from_chrome: impl Read + Send + 'static,
    ) -> std::io::Result<Self> {
        let shared = Arc::new(Shared::default());
        let reader = shared.clone();
        std::thread::Builder::new()
            .name("asm-broker-cdp".into())
            .spawn(move || read_loop(BufReader::new(from_chrome), &reader))?;
        Ok(Self { writer: Mutex::new(Box::new(to_chrome)), next_id: AtomicU64::new(1), shared })
    }

    /// Send `method` (to `session` when set, else to the browser) and wait up to
    /// `timeout` for its result.
    pub(crate) fn call(
        &self, method: &str, params: Value, session: Option<&str>, timeout: Duration,
    ) -> Result<Value, CdpError> {
        let params = serde_json::to_vec(&params).map_err(|e| CdpError::Protocol(e.to_string()))?;
        self.call_raw(method, &params, session, timeout)
    }

    /// [`Cdp::call`] with `params` already serialized as a JSON object. The frame is
    /// built in a buffer zeroized after sending, so secret parameters serialized by the
    /// caller into a zeroized buffer leave no other copy behind.
    pub(crate) fn call_raw(
        &self, method: &str, params: &[u8], session: Option<&str>, timeout: Duration,
    ) -> Result<Value, CdpError> {
        if self.is_closed() {
            return Err(CdpError::Closed);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let head = match session {
            Some(session) => format!(
                "{{\"id\":{id},\"method\":{},\"sessionId\":{},\"params\":",
                Value::from(method), Value::from(session)),
            None => format!("{{\"id\":{id},\"method\":{},\"params\":", Value::from(method)),
        };
        // Sized up front: growing would leave an unzeroized copy in the old allocation.
        let mut bytes = Zeroizing::new(Vec::with_capacity(head.len() + params.len() + 2));
        bytes.extend_from_slice(head.as_bytes());
        bytes.extend_from_slice(params);
        bytes.extend_from_slice(b"}\0");
        let (tx, rx) = mpsc::channel();
        lock(&self.shared.pending).insert(id, tx);
        // The reader may have seen EOF after the check above; it then dropped every
        // sender it knew of, but not this one.
        if self.is_closed() {
            lock(&self.shared.pending).remove(&id);
            return Err(CdpError::Closed);
        }
        let sent = {
            let mut w = lock(&self.writer);
            w.write_all(&bytes).and_then(|()| w.flush())
        };
        drop(bytes);
        if sent.is_err() {
            // A broken pipe: Chrome is gone (the write end never raises SIGPIPE).
            self.shared.closed.store(true, Ordering::Release);
            lock(&self.shared.pending).remove(&id);
            return Err(CdpError::Closed);
        }
        match rx.recv_timeout(timeout) {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(message)) => Err(CdpError::Protocol(message)),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                lock(&self.shared.pending).remove(&id);
                Err(CdpError::Timeout(method.to_owned()))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(CdpError::Closed),
        }
    }

    /// The pipe from Chrome reached its end.
    pub(crate) fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Acquire)
    }

    /// Events received since the last call, oldest first.
    pub(crate) fn drain_events(&self) -> Vec<Event> {
        lock(&self.shared.events).drain(..).collect()
    }
}

fn read_loop(mut from_chrome: impl BufRead, shared: &Shared) {
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match from_chrome.read_until(0, &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if buf.last() == Some(&0) {
            buf.pop();
        }
        let Ok(mut message) = serde_json::from_slice::<Value>(&buf) else { continue };
        if let Some(id) = message.get("id").and_then(Value::as_u64) {
            let reply = match message.get_mut("error") {
                Some(error) => Err(error.get("message").and_then(Value::as_str)
                    .unwrap_or("the browser returned an error").to_owned()),
                None => Ok(message.get_mut("result").map(Value::take).unwrap_or(Value::Null)),
            };
            if let Some(tx) = lock(&shared.pending).remove(&id) {
                let _ = tx.send(reply);
            }
        } else if let Some(method) = message.get("method").and_then(Value::as_str) {
            let event = Event {
                method: method.to_owned(),
                session: message.get("sessionId").and_then(Value::as_str).map(str::to_owned),
                params: message.get_mut("params").map(Value::take).unwrap_or(Value::Null),
            };
            let mut events = lock(&shared.events);
            if events.len() == MAX_EVENTS {
                events.pop_front();
            }
            events.push_back(event);
        }
    }
    shared.closed.store(true, Ordering::Release);
    // Wake every waiting caller with `Closed`.
    lock(&shared.pending).clear();
}

/// Startup on a fresh Chrome: wait for its first page, attach to it (flattened
/// session), enable the domains the broker uses, and return the session id.
pub(crate) fn attach_first_page(cdp: &Cdp, timeout: Duration) -> Result<String, CdpError> {
    let deadline = std::time::Instant::now() + timeout;
    let target = loop {
        let targets = cdp.call("Target.getTargets", json!({}), None, CALL_TIMEOUT)?;
        let page = targets["targetInfos"].as_array().into_iter().flatten()
            .find(|t| t["type"] == "page")
            .and_then(|t| t["targetId"].as_str())
            .map(str::to_owned);
        match page {
            Some(page) => break page,
            None if std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            None => return Err(CdpError::Protocol("the browser opened no page".into())),
        }
    };
    let attached = cdp.call("Target.attachToTarget", json!({ "targetId": target, "flatten": true }), None, CALL_TIMEOUT)?;
    let session = attached["sessionId"].as_str()
        .ok_or_else(|| CdpError::Protocol("the browser did not attach to its page".into()))?
        .to_owned();
    for domain in ["Page.enable", "Runtime.enable", "DOMStorage.enable"] {
        cdp.call(domain, json!({}), Some(&session), CALL_TIMEOUT)?;
    }
    Ok(session)
}

/// Timeout of one ordinary call.
pub(crate) const CALL_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// A fake Chrome on the other ends of two pipes: answers each command with its
    /// method name, or an error for `Fail.*`, and emits one event first.
    fn fake_chrome(mut commands: std::io::PipeReader, mut replies: std::io::PipeWriter) {
        std::thread::spawn(move || {
            replies.write_all(b"{\"method\":\"Target.targetCreated\",\"params\":{\"x\":1}}\0").unwrap();
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                if commands.read(&mut byte).unwrap_or(0) == 0 {
                    return;
                }
                if byte[0] != 0 {
                    buf.push(byte[0]);
                    continue;
                }
                let message: Value = serde_json::from_slice(&buf).unwrap();
                buf.clear();
                let id = message["id"].as_u64().unwrap();
                let method = message["method"].as_str().unwrap();
                if method == "Quit" {
                    return;
                }
                let reply = if method.starts_with("Fail.") {
                    json!({ "id": id, "error": { "code": -32000, "message": "no such thing" } })
                } else if method == "Slow.call" {
                    continue;
                } else {
                    json!({ "id": id, "result": { "method": method, "session": message["sessionId"] } })
                };
                let mut bytes = serde_json::to_vec(&reply).unwrap();
                bytes.push(0);
                replies.write_all(&bytes).unwrap();
            }
        });
    }

    #[test]
    fn routes_replies_by_id_and_queues_events() {
        let (to_read, to_write) = std::io::pipe().unwrap();
        let (from_read, from_write) = std::io::pipe().unwrap();
        fake_chrome(to_read, from_write);
        let cdp = Cdp::new(to_write, from_read).unwrap();
        let t = Duration::from_secs(5);
        assert_eq!(cdp.call("Page.enable", json!({}), Some("s1"), t).unwrap(),
            json!({ "method": "Page.enable", "session": "s1" }));
        assert_eq!(cdp.call("Fail.x", json!({}), None, t).unwrap_err(), CdpError::Protocol("no such thing".into()));
        assert_eq!(cdp.call("Slow.call", json!({}), None, Duration::from_millis(50)).unwrap_err(),
            CdpError::Timeout("Slow.call".into()));
        let events = cdp.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].method, "Target.targetCreated");
        assert!(cdp.drain_events().is_empty());
        let _ = cdp.call("Quit", json!({}), None, Duration::from_millis(500));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !cdp.is_closed() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(cdp.is_closed());
        assert_eq!(cdp.call("Page.enable", json!({}), None, t).unwrap_err(), CdpError::Closed);
    }
}
