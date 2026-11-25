//! Activity log: a persistent audit trail of pairing, requests, leases, proxy traffic that
//! carried a substitution (or was refused) and vault changes, in the `activity` table.
//!
//! Rows never hold secret values or the values of update/add requests. Events are sent
//! over a channel to one writer thread (the proxy's log thread and request handlers never
//! wait on SQLite); the writer maps proxy value files to leases, appends rows in batches
//! and fires the observer topic `activity` at most four times a second.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use asm_proto::time::{fmt_unix, parse_unix};
use asm_proto::wire::{LeaseMode, RequestResult};
use serde_json::{Map, Value, json};

use super::requests::{Detail, Pending};
use super::{Core, TOPIC_ACTIVITY, lock, now, to_system_time};
use crate::ffi::{self, ManagerObserver};
use crate::proxy::audit::{self, AuditLine};
use crate::proxy::{EventSink, ProxyEvent};
use crate::store::{ActivityFilter, LeaseRecord, NewActivity, Store, VaultRecord};
use crate::vault::{VaultConfig, VaultStatus};

/// Rows older than this are pruned by the sweep.
pub const KEEP_SECS: i64 = 30 * 86_400;
/// At most this many rows are kept.
pub const KEEP_ROWS: u32 = 50_000;
/// `list_activity` page size when the query's limit is 0, and the largest page.
const PAGE_DEFAULT: u32 = 200;
const PAGE_MAX: u32 = 1000;
const NOTIFY_EVERY: Duration = Duration::from_millis(250);
const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Pairing,
    Requests,
    Leases,
    Proxy,
    Vaults,
    Generators,
    Ssh,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Pairing => "pairing",
            Category::Requests => "requests",
            Category::Leases => "leases",
            Category::Proxy => "proxy",
            Category::Vaults => "vaults",
            Category::Generators => "generators",
            Category::Ssh => "ssh",
        }
    }
}

/// One activity row before it is written.
#[derive(Debug, Clone)]
pub struct Event {
    pub at: i64,
    pub category: Category,
    pub kind: &'static str,
    pub host_id: Option<String>,
    pub secret: Option<String>,
    pub summary: String,
    pub detail: Option<Value>,
}

impl Event {
    pub fn new(category: Category, kind: &'static str, summary: impl Into<String>) -> Self {
        Self {
            at: now(),
            category,
            kind,
            host_id: None,
            secret: None,
            summary: summary.into(),
            detail: None,
        }
    }

    pub fn host(mut self, host_id: Option<&str>) -> Self {
        self.host_id = host_id.filter(|h| !h.is_empty()).map(str::to_string);
        self
    }

    pub fn secret(mut self, secret: &str) -> Self {
        self.secret = Some(secret.to_string());
        self
    }

    pub fn detail(mut self, detail: Value) -> Self {
        self.detail = Some(detail);
        self
    }

    fn into_row(self) -> NewActivity {
        let request_id = self
            .detail
            .as_ref()
            .and_then(|d| d.get("request_id"))
            .and_then(Value::as_str)
            .map(str::to_string);
        NewActivity {
            at: fmt_unix(self.at),
            category: self.category.as_str(),
            kind: self.kind,
            host_id: self.host_id,
            secret: self.secret,
            summary: self.summary,
            detail: self.detail.map(|d| d.to_string()),
            request_id,
        }
    }
}

enum Msg {
    Event(Box<Event>),
    Proxy(Box<ProxyEvent>),
    Flush(mpsc::Sender<()>),
    Stop,
}

/// Handle to the writer thread.
pub struct ActivityLog {
    tx: mpsc::Sender<Msg>,
}

impl ActivityLog {
    pub fn start(store: Arc<Store>, observer: Arc<dyn ManagerObserver>) -> Self {
        let (tx, rx) = mpsc::channel();
        if let Err(e) = std::thread::Builder::new()
            .name("asm-activity".into())
            .spawn(move || writer(rx, &store, observer.as_ref()))
        {
            log::error!("cannot start the activity writer: {e}");
        }
        Self { tx }
    }

    pub fn record(&self, e: Event) {
        let _ = self.tx.send(Msg::Event(Box::new(e)));
    }

    /// Callback for the proxy supervisor (non-blocking).
    pub fn proxy_sink(&self) -> EventSink {
        let tx = self.tx.clone();
        Arc::new(move |e| {
            let _ = tx.send(Msg::Proxy(Box::new(e)));
        })
    }

    /// Wait until every event sent so far is written.
    pub fn flush(&self) {
        let (tx, rx) = mpsc::channel();
        if self.tx.send(Msg::Flush(tx)).is_ok() {
            let _ = rx.recv_timeout(FLUSH_TIMEOUT);
        }
    }

    /// Write what is queued, then end the writer.
    pub fn stop(&self) {
        let _ = self.tx.send(Msg::Stop);
    }
}

fn writer(rx: mpsc::Receiver<Msg>, store: &Store, observer: &dyn ManagerObserver) {
    let mut last_notify: Option<Instant> = None;
    let mut dirty = false;
    loop {
        let first = if dirty {
            let wait =
                last_notify.map_or(Duration::ZERO, |t| NOTIFY_EVERY.saturating_sub(t.elapsed()));
            match rx.recv_timeout(wait) {
                Ok(m) => Some(m),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        } else {
            match rx.recv() {
                Ok(m) => Some(m),
                Err(_) => break,
            }
        };
        let mut rows = Vec::new();
        let mut flushes = Vec::new();
        let mut stop = false;
        let mut leases: HashMap<String, Option<LeaseRecord>> = HashMap::new();
        for m in first
            .into_iter()
            .chain(std::iter::from_fn(|| rx.try_recv().ok()))
        {
            match m {
                Msg::Event(e) => rows.push(e.into_row()),
                Msg::Proxy(p) => {
                    let lookup = |id: &str| {
                        leases
                            .entry(id.to_string())
                            .or_insert_with(|| store.get_lease(id).ok().flatten())
                            .clone()
                    };
                    rows.push(proxy_event(*p, lookup).into_row());
                }
                Msg::Flush(tx) => flushes.push(tx),
                Msg::Stop => stop = true,
            }
        }
        if !rows.is_empty() {
            match store.insert_activity(&rows) {
                Ok(()) => dirty = true,
                Err(e) => log::error!("activity log: {}", e.message),
            }
        }
        for f in flushes {
            let _ = f.send(());
        }
        if dirty && (stop || last_notify.is_none_or(|t| t.elapsed() >= NOTIFY_EVERY)) {
            observer.changed(TOPIC_ACTIVITY.to_string());
            last_notify = Some(Instant::now());
            dirty = false;
        }
        if stop {
            break;
        }
    }
}

/// Map a proxy event to a row; `lease` looks a lease up by id.
pub(crate) fn proxy_event(
    ev: ProxyEvent,
    mut lease: impl FnMut(&str) -> Option<LeaseRecord>,
) -> Event {
    match ev {
        ProxyEvent::Lifecycle { kind, summary } => Event::new(Category::Proxy, kind, summary),
        ProxyEvent::Request(a) => request_line_event(&a, &mut lease),
    }
}

fn request_line_event(a: &AuditLine, lease: &mut impl FnMut(&str) -> Option<LeaseRecord>) -> Event {
    let target = format!("{} {}{}", a.method, a.host, a.path);
    let status = a.status.map_or_else(|| "?".to_string(), |s| s.to_string());
    let mut subs = Vec::new();
    let mut locations: Vec<&str> = Vec::new();
    let mut known: Option<LeaseRecord> = None;
    for s in &a.swaps {
        let mapped = audit::lease_of_value_path(&s.value_path)
            .and_then(|(id, n)| lease(&id).map(|l| (l, n)));
        let (lease_id, field) = match &mapped {
            Some((l, n)) => (
                Some(l.id.clone()),
                l.fields.get(*n).map(|f| f.field.clone()),
            ),
            None => (None, None),
        };
        subs.push(json!({ "lease_id": lease_id, "field": field, "locations": s.locations }));
        for loc in &s.locations {
            if !locations.contains(&loc.as_str()) {
                locations.push(loc);
            }
        }
        if known.is_none() {
            known = mapped.map(|(l, _)| l);
        }
    }
    let reject_reason = a.rejected.as_ref().and_then(|r| r.reason.clone());
    if known.is_none() {
        known = a
            .rejected
            .as_ref()
            .and_then(|r| r.value_path.as_deref())
            .and_then(audit::lease_of_value_path)
            .and_then(|(id, _)| lease(&id));
    }
    let (kind, summary) = match &a.rejected {
        Some(_) => (
            "rejected",
            format!(
                "{target} → {status}, rejected: {}",
                reject_reason
                    .as_deref()
                    .map_or("refused by the secrets transform", audit::reject_text)
            ),
        ),
        None => (
            "substitution",
            format!(
                "{target} → {status}, substituted in {}",
                locations.join(", ")
            ),
        ),
    };
    let e = Event::new(Category::Proxy, kind, summary).detail(json!({
        "method": a.method,
        "host": a.host,
        "path": a.path,
        "status": a.status,
        "remote_addr": a.remote_addr,
        "substitutions": subs,
        "reject_reason": reject_reason,
        "lease_id": known.as_ref().map(|l| l.id.clone()),
    }));
    match &known {
        Some(l) => e.host(Some(&l.host_id)).secret(&l.name),
        None => e,
    }
}

/// `"1 h"`, `"3 days"`, `"unlimited"`, …
pub(crate) fn fmt_duration(secs: Option<i64>) -> String {
    let Some(s) = secs else {
        return "unlimited".to_string();
    };
    if let Some((label, _)) = asm_proto::wire::LEASE_DURATIONS
        .iter()
        .find(|(_, d)| d.is_some_and(|d| d as i64 == s))
    {
        return (*label).to_string();
    }
    match s {
        s if s < 60 => format!("{s} s"),
        s if s < 3600 => format!("{} min", s / 60),
        s if s < 172_800 => format!("{} h", s / 3600),
        s => format!("{} days", s / 86_400),
    }
}

fn hosts_text(hosts: &[String]) -> String {
    if hosts.iter().any(|h| h == "*") {
        "any host".to_string()
    } else {
        hosts.join(", ")
    }
}

fn mode_text(m: LeaseMode) -> &'static str {
    match m {
        LeaseMode::Sentinel => "sentinel",
        LeaseMode::Raw => "raw",
    }
}

fn lease_event(kind: &'static str, l: &LeaseRecord, summary: String) -> Event {
    Event::new(Category::Leases, kind, summary)
        .host(Some(&l.host_id))
        .secret(&l.name)
        .detail(json!({
            "lease_id": l.id,
            "vault": l.vault_name,
            "mode": mode_text(l.mode),
            "hosts": l.hosts,
            "fields": l.fields.iter().map(|f| f.field.as_str()).collect::<Vec<_>>(),
            "created_at": fmt_unix(l.created_at),
            "expires_at": l.expires_at.map(fmt_unix),
            "source_kind": l.source_kind,
            "generation": l.generation,
            "generator_revision": l.generator_revision,
            "credential_expires_at": l.credential_expires_at.map(fmt_unix),
            "credential_version": l.credential_version,
            "agent": l.agent,
            "reason": l.reason,
        }))
}

/// Base JSON detail of a request (never values).
fn request_detail(p: &Pending) -> Map<String, Value> {
    let mut d = Map::new();
    d.insert("request_id".into(), json!(p.id));
    d.insert("request".into(), json!(p.kind_str()));
    if !p.agent.is_empty() {
        d.insert("agent".into(), json!(p.agent));
    }
    match &p.detail {
        Detail::Pair {
            info,
            address,
            repair,
            ..
        } => {
            d.insert("address".into(), json!(address));
            d.insert(
                "host_info".into(),
                serde_json::to_value(info).unwrap_or(Value::Null),
            );
            if let Some(r) = repair {
                d.insert(
                    "repair".into(),
                    json!({ "kind": r.kind(), "host_id": r.host_id, "host_name": r.host_name }),
                );
            }
        }
        Detail::Get(g) => {
            match &g.target {
                super::requests::GetTarget::Vault(s) => { d.insert("vault".into(), json!(s.vault_name)); }
                super::requests::GetTarget::Generated(target) => {
                    d.insert("generator_choices".into(), json!(target.candidates.iter()
                        .map(|c| (&c.generator_id, c.revision)).collect::<Vec<_>>()));
                    d.insert("requested_generation".into(), json!(target.requested_generation));
                }
            }
            d.insert("fields".into(), json!(g.wanted_fields));
            d.insert("raw_requested".into(), json!(g.mode == super::requests::RequestedMode::Raw));
            d.insert("requested_hosts".into(), json!(g.requested_hosts));
            d.insert("reason".into(), json!(g.reason));
        }
        Detail::Update(u) => {
            d.insert("vault".into(), json!(u.secret.vault_name));
            d.insert("field".into(), json!(u.field));
        }
        Detail::Add(_) => {}
        Detail::Login(l) => {
            d.insert("vault".into(), json!(l.secret.vault_name));
            d.insert("url".into(), json!(l.url));
            d.insert("fill_origins".into(), json!(l.fill_origins));
            d.insert("reason".into(), json!(l.reason));
        }
        Detail::Ssh(s) => {
            d.insert("targets".into(), json!(s.targets.iter().map(|t| &t.name).collect::<Vec<_>>()));
            d.insert("access".into(), json!(s.access));
            d.insert("grants".into(), json!(s.grants));
            d.insert("user".into(), json!(s.user));
            d.insert("reason".into(), json!(s.reason));
        }
        Detail::SshExtend(e) => {
            d.insert("lease_id".into(), json!(e.lease_id));
            d.insert("reason".into(), json!(e.reason));
        }
    }
    d
}

fn request_event(p: &Pending, kind: &'static str, summary: String, extra: Value) -> Event {
    let (category, secret) = match &p.detail {
        Detail::Pair { .. } => (Category::Pairing, None),
        Detail::Get(g) => (Category::Requests, Some(g.target.display())),
        Detail::Update(u) => (Category::Requests, Some(u.secret.display.as_str())),
        Detail::Add(a) => (Category::Requests, Some(a.name.as_str())),
        Detail::Login(l) => (Category::Requests, Some(l.secret.display.as_str())),
        Detail::Ssh(_) | Detail::SshExtend(_) => (Category::Requests, None),
    };
    let mut d = request_detail(p);
    if let Value::Object(x) = extra {
        d.extend(x);
    }
    let e = Event::new(category, kind, summary)
        .host(p.host_id.as_deref())
        .detail(Value::Object(d));
    match secret {
        Some(s) => e.secret(s),
        None => e,
    }
}

/// Short subject of a request for summaries: `get DEMO_TOKEN (raw)`, `pairing of box`.
fn subject(p: &Pending) -> String {
    match &p.detail {
        Detail::Pair { info, .. } => format!("pairing of {}", info.hostname),
        _ => p.summary(),
    }
}

/// A new pending request (popup shown).
pub(crate) fn requested(p: &Pending) -> Event {
    let summary = match &p.detail {
        Detail::Pair {
            info,
            address,
            repair,
            ..
        } => {
            let about = match repair {
                Some(r) if r.proof.is_some() => format!(" (re-pairing {})", r.host_name),
                Some(r) => format!(" (looks like {})", r.host_name),
                None => String::new(),
            };
            format!(
                "pairing requested by {} from {address}{about}",
                info.hostname
            )
        }
        Detail::Get(g) if g.requested_hosts.is_empty() => {
            format!("{} requested: {}", p.summary(), g.reason)
        }
        Detail::Get(g) => format!(
            "{} requested for {}: {}",
            p.summary(),
            hosts_text(&g.requested_hosts),
            g.reason
        ),
        Detail::Login(l) => format!("{} requested for {}: {}", p.summary(), l.url, l.reason),
        _ => format!("{} requested", p.summary()),
    };
    request_event(p, "requested", summary, Value::Null)
}

/// A request that ended without approval (`denied`, `failed`, `expired`, `cancelled`).
pub(crate) fn ended(p: &Pending, kind: &'static str, reason: Option<&str>) -> Event {
    let summary = match reason {
        Some(r) => format!("{} {kind}: {r}", subject(p)),
        None => format!("{} {kind}", subject(p)),
    };
    request_event(p, kind, summary, json!({ "deny_reason": reason }))
}

/// An approved `asm login` opened its sign-in browser; the request ends at hand-over.
pub(crate) fn broker_started(p: &Pending, fill_origins: &[String]) -> Event {
    request_event(
        p,
        "browser_opened",
        format!("{}: sign-in browser opened for {}", subject(p), fill_origins.join(", ")),
        json!({ "approved_fill_origins": fill_origins }),
    )
}

/// An approved request; `result` is what the host receives (values are not read from it).
pub(crate) fn approved(p: &Pending, result: Option<&RequestResult>, t: i64) -> Event {
    match (&p.detail, result) {
        (Detail::Pair { .. }, _) => request_event(
            p,
            "approved",
            format!("{} approved as \"{}\"", subject(p), p.host_label),
            json!({ "name": p.host_label }),
        ),
        (_, Some(RequestResult::Get(g))) => {
            let secs = g.expires_at.as_deref().and_then(parse_unix).map(|e| e - t);
            let what = match g.mode {
                LeaseMode::Sentinel => format!("sentinel for {}", hosts_text(&g.hosts)),
                LeaseMode::Raw => "raw value".to_string(),
            };
            request_event(
                p,
                "approved",
                format!("{} approved: {what}, {}", subject(p), fmt_duration(secs)),
                json!({
                    "lease_id": g.lease_id,
                    "mode": mode_text(g.mode),
                    "approved_hosts": g.hosts,
                    "duration_secs": secs,
                    "expires_at": g.expires_at,
                    "generation": g.generation,
                    "credential_expires_at": g.credential_expires_at,
                    "credential_version": g.credential_version,
                }),
            )
        }
        (_, Some(RequestResult::Write(w))) => {
            let verb = if matches!(p.detail, Detail::Add(_)) {
                "stored in"
            } else {
                "written to"
            };
            request_event(
                p,
                "approved",
                format!("{} approved, {verb} {}", subject(p), w.vault),
                json!({ "vault": w.vault }),
            )
        }
        (_, Some(RequestResult::Ssh(s))) => {
            let secs = parse_unix(&s.expires_at).map(|e| e - t);
            let names: Vec<&str> = s.targets.iter().map(|t| t.name.as_str()).collect();
            request_event(
                p,
                "approved",
                format!("{} approved: {} to {}, {}", subject(p), match s.access {
                    asm_proto::ssh::SshAccess::User => format!("SSH as {}", s.user.as_deref().unwrap_or("-")),
                    access => format!("{} SSH", access.as_str()),
                }, names.join(", "), fmt_duration(secs)),
                json!({
                    "lease_id": s.lease_id,
                    "access": s.access,
                    "grants": s.grants,
                    "user": s.user,
                    "targets": names,
                    "duration_secs": secs,
                    "expires_at": s.expires_at,
                }),
            )
        }
        (_, None) => request_event(
            p,
            "approved",
            format!("{} approved", subject(p)),
            Value::Null,
        ),
    }
}

fn vault_type(c: &VaultConfig) -> &'static str {
    match c {
        VaultConfig::Bitwarden(_) => "bitwarden",
        VaultConfig::EnvFile { .. } => "env_file",
        VaultConfig::Keychain => "keychain",
    }
}

/// Vault detail without credentials (no client secret, never a master password).
fn vault_detail(id: &str, name: &str, config: &VaultConfig) -> Value {
    let mut d = json!({ "vault_id": id, "vault": name, "type": vault_type(config) });
    match config {
        VaultConfig::Bitwarden(b) => {
            d["server_url"] = json!(b.server_url);
            d["email"] = json!(b.email);
            d["collections"] = json!(b.collections);
            d["personal"] = json!(b.personal);
        }
        VaultConfig::EnvFile { path } => d["path"] = json!(path),
        VaultConfig::Keychain => {}
    }
    d
}

pub(crate) fn vault_event(
    kind: &'static str,
    id: &str,
    name: &str,
    config: &VaultConfig,
    summary: String,
) -> Event {
    Event::new(Category::Vaults, kind, summary).detail(vault_detail(id, name, config))
}

/// `vault <name>: unlock failed: <message>` (the message is `bw`'s, never the password).
pub(crate) fn unlock_failed(id: &str, name: &str, config: &VaultConfig, msg: &str) -> Event {
    let msg = msg.strip_prefix("unlock failed: ").unwrap_or(msg);
    let mut e = vault_event(
        "unlock_failed",
        id,
        name,
        config,
        format!("vault {name}: unlock failed: {msg}"),
    );
    if let Some(d) = e.detail.as_mut() {
        d["message"] = json!(msg);
    }
    e
}

impl Core {
    pub fn log(&self, e: Event) {
        self.activity.record(e);
    }

    pub(crate) fn log_lease_created(&self, l: &LeaseRecord) {
        let secs = l.expires_at.map(|e| e - l.created_at);
        let summary = match l.mode {
            LeaseMode::Sentinel => format!(
                "sentinel lease on {} for {}, {}",
                l.name,
                hosts_text(&l.hosts),
                fmt_duration(secs)
            ),
            LeaseMode::Raw => format!(
                "raw lease on {} (value delivered), {}",
                l.name,
                fmt_duration(secs)
            ),
        };
        self.log(lease_event("created", l, summary));
    }

    /// `by`: `operator`, `host revoked`, `secret updated`, `vault removed`.
    pub(crate) fn log_lease_revoked(&self, l: &LeaseRecord, by: &str) {
        let summary = if by == "operator" {
            format!("lease on {} revoked by the operator", l.name)
        } else {
            format!("lease on {} revoked: {by}", l.name)
        };
        let mut e = lease_event("revoked", l, summary);
        if let Some(Value::Object(d)) = e.detail.as_mut() {
            d.insert("revoked_by".into(), json!(by));
        }
        self.log(e);
    }

    pub(crate) fn log_lease_expired(&self, l: &LeaseRecord) {
        self.log(lease_event(
            "expired",
            l,
            format!("lease on {} expired", l.name),
        ));
    }

    pub(crate) fn log_lease_suspended(&self, l: &LeaseRecord, why: &str) {
        let mut e = lease_event(
            "suspended",
            l,
            format!("lease on {} suspended: {why}", l.name),
        );
        if let Some(Value::Object(d)) = e.detail.as_mut() {
            d.insert("message".into(), json!(why));
        }
        self.log(e);
    }

    pub(crate) fn log_lease_resumed(&self, l: &LeaseRecord) {
        self.log(lease_event(
            "resumed",
            l,
            format!("lease on {} resumed", l.name),
        ));
    }

    /// Record a vault's readiness without logging (after an explicit unlock or add).
    pub(crate) fn vault_seen(&self, id: &str, ready: bool) {
        lock(&self.vault_ready).insert(id.to_string(), ready);
    }

    /// Log vaults that became unavailable or available since the last check. Vaults seen
    /// for the first time are recorded quietly.
    pub(crate) fn track_vaults(&self) {
        let Ok(vaults) = self.store.list_vaults() else {
            return;
        };
        let errors = lock(&self.vault_errors).clone();
        let statuses: Vec<(VaultRecord, VaultStatus)> = vaults
            .into_iter()
            .map(|v| {
                let s = match self.registry.get(&v.id) {
                    Some(e) => e.provider.status(),
                    None => VaultStatus::Error(
                        errors
                            .get(&v.id)
                            .cloned()
                            .unwrap_or_else(|| "vault could not be started".into()),
                    ),
                };
                (v, s)
            })
            .collect();
        let mut events = Vec::new();
        {
            let mut seen = lock(&self.vault_ready);
            seen.retain(|id, _| statuses.iter().any(|(v, _)| &v.id == id));
            for (v, s) in &statuses {
                let ready = *s == VaultStatus::Ready;
                match seen.insert(v.id.clone(), ready) {
                    Some(true) if !ready => {
                        let why = match s {
                            VaultStatus::Locked => "locked".to_string(),
                            VaultStatus::Error(m) => m.clone(),
                            VaultStatus::Ready => unreachable!(),
                        };
                        let mut e = vault_event(
                            "unavailable",
                            &v.id,
                            &v.name,
                            &v.config,
                            format!("vault {} unavailable: {why}", v.name),
                        );
                        if let Some(d) = e.detail.as_mut() {
                            d["message"] = json!(why);
                        }
                        events.push(e);
                    }
                    Some(false) if ready => events.push(vault_event(
                        "available",
                        &v.id,
                        &v.name,
                        &v.config,
                        format!("vault {} available again", v.name),
                    )),
                    _ => {}
                }
            }
        }
        for e in events {
            self.log(e);
        }
    }

    /// `list_activity` over FFI: newest first; written events are flushed first.
    pub fn list_activity(&self, q: ffi::ActivityQuery) -> Vec<ffi::ActivityEntry> {
        self.activity.flush();
        let f = ActivityFilter {
            categories: q.categories,
            host_id: q.host_id.filter(|h| !h.is_empty()),
            search: q.search.trim().to_string(),
            before_id: q.before_id,
            limit: match q.limit {
                0 => PAGE_DEFAULT,
                n => n.min(PAGE_MAX),
            },
        };
        match self.store.list_activity(&f) {
            Ok(rows) => rows
                .into_iter()
                .map(|r| ffi::ActivityEntry {
                    id: r.id,
                    at: to_system_time(parse_unix(&r.at).unwrap_or(0)),
                    category: r.category,
                    kind: r.kind,
                    host_id: r.host_id,
                    host_label: r.host_label,
                    secret: r.secret,
                    summary: r.summary,
                    detail: r.detail,
                })
                .collect(),
            Err(e) => {
                log::error!("list activity: {}", e.message);
                Vec::new()
            }
        }
    }

    /// `activity_row_for_request` over FFI: the row recording how a resolved request ended;
    /// written events are flushed first.
    pub fn activity_row_for_request(&self, request_id: &str) -> Option<i64> {
        self.activity.flush();
        self.store
            .activity_row_for_request(request_id)
            .unwrap_or_else(|e| {
                log::error!("activity row for request: {}", e.message);
                None
            })
    }

    /// Retention (called by the sweep).
    pub(crate) fn prune_activity(&self, t: i64) {
        if let Err(e) = self
            .store
            .prune_activity(&fmt_unix(t - KEEP_SECS), KEEP_ROWS)
        {
            log::error!("prune activity: {}", e.message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::audit::{Reject, Swap};
    use crate::store::LeaseField;
    use std::sync::Mutex;

    fn lease() -> LeaseRecord {
        LeaseRecord {
            id: "7637e5fd-7d0d-491b-93e6-45096c02e94c".into(),
            host_id: "h1".into(),
            vault_id: "v1".into(),
            vault_name: "demo".into(),
            secret_key: "GitHub".into(),
            name: "GitHub".into(),
            mode: LeaseMode::Sentinel,
            fields: vec![
                LeaseField {
                    field: "username".into(),
                    sentinel: None,
                    path: "GitHub.username".into(),
                },
                LeaseField {
                    field: "password".into(),
                    sentinel: Some("asm_x".into()),
                    path: "GitHub.password".into(),
                },
            ],
            hosts: vec!["httpbingo.org".into()],
            reason: "r".into(),
            agent: "a".into(),
            created_at: 100,
            expires_at: Some(3700),
            revoked_at: None,
            source_kind: asm_proto::generators::SourceKind::Vault,
            generation: None,
            generator_revision: None,
            credential_expires_at: None,
            approval_order: None,
            credential_version: 0,
            requested_generation: None,
            login: None,
        }
    }

    fn lookup(id: &str) -> Option<LeaseRecord> {
        (id == "7637e5fd-7d0d-491b-93e6-45096c02e94c").then(lease)
    }

    #[test]
    fn proxy_substitution_maps_to_its_lease() {
        let line = r#"{"time":"2026-11-16T16:50:34.281492+11:00","level":"INFO","msg":"request","audit":{"host":"httpbingo.org","method":"GET","path":"/headers?token=abc","remote_addr":"127.0.0.1:57217","status_code":200},"request_transforms":[{"name":"secrets","action":"allow","annotations":{"swapped":[{"secret":"/var/folders/T/net.thinkscape.asm/values/7637e5fd-7d0d-491b-93e6-45096c02e94c.1","locations":["header:X-Key","query:token"]}]}}]}"#;
        let a = audit::parse(line).unwrap();
        let e = proxy_event(ProxyEvent::Request(a), lookup);
        assert_eq!(e.category, Category::Proxy);
        assert_eq!(e.kind, "substitution");
        assert_eq!(e.host_id.as_deref(), Some("h1"));
        assert_eq!(e.secret.as_deref(), Some("GitHub"));
        assert_eq!(
            e.summary,
            "GET httpbingo.org/headers → 200, substituted in header:X-Key, query:token"
        );
        let d = e.detail.unwrap();
        assert_eq!(d["lease_id"], "7637e5fd-7d0d-491b-93e6-45096c02e94c");
        assert_eq!(d["substitutions"][0]["field"], "password");
        assert_eq!(d["path"], "/headers", "no query string");
        assert!(!d.to_string().contains("abc"));
    }

    #[test]
    fn proxy_rejection_with_unknown_lease() {
        let a = AuditLine {
            method: "GET".into(),
            host: "example.com".into(),
            path: "/".into(),
            status: Some(403),
            remote_addr: "127.0.0.1:1".into(),
            swaps: vec![],
            rejected: Some(Reject {
                reason: Some("sentinel_not_valid".into()),
                value_path: Some("/data/proxy/blocked.value".into()),
            }),
        };
        let e = proxy_event(ProxyEvent::Request(a.clone()), lookup);
        assert_eq!(e.kind, "rejected");
        assert_eq!(e.host_id, None);
        assert_eq!(
            e.summary,
            "GET example.com/ → 403, rejected: sentinel not valid for this host or scheme"
        );
        // A refused sentinel of a known lease names it.
        let a = AuditLine {
            rejected: Some(Reject {
                reason: Some("sentinel_not_valid".into()),
                value_path: Some("/v/7637e5fd-7d0d-491b-93e6-45096c02e94c.1".into()),
            }),
            ..a
        };
        let e = proxy_event(ProxyEvent::Request(a), lookup);
        assert_eq!(e.secret.as_deref(), Some("GitHub"));
        // Swap of a lease that no longer exists.
        let a = AuditLine {
            swaps: vec![Swap {
                value_path: "/v/gone.0".into(),
                locations: vec!["body".into()],
            }],
            rejected: None,
            ..AuditLine::default()
        };
        let e = proxy_event(ProxyEvent::Request(a), lookup);
        assert_eq!(e.kind, "substitution");
        assert_eq!(e.secret, None);
    }

    #[test]
    fn durations() {
        assert_eq!(fmt_duration(None), "unlimited");
        assert_eq!(fmt_duration(Some(3600)), "1 h");
        assert_eq!(fmt_duration(Some(259_200)), "3 days");
        assert_eq!(fmt_duration(Some(3599)), "59 min");
    }

    #[test]
    fn writer_batches_and_notifies() {
        struct Count(Mutex<Vec<String>>);
        impl ManagerObserver for Count {
            fn changed(&self, topic: String) {
                self.0.lock().unwrap().push(topic);
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&dir.path().join("asm.db")).unwrap());
        let obs = Arc::new(Count(Mutex::new(Vec::new())));
        let log = ActivityLog::start(store.clone(), obs.clone());
        for i in 0..50 {
            log.record(Event::new(Category::Vaults, "added", format!("row {i}")));
        }
        (log.proxy_sink())(ProxyEvent::Lifecycle {
            kind: "started",
            summary: "proxy started (pid 1)".into(),
        });
        log.flush();
        let rows = store
            .list_activity(&ActivityFilter {
                limit: 100,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(rows.len(), 51);
        assert_eq!(rows[0].summary, "proxy started (pid 1)");
        assert!(rows.iter().all(|r| r.at.ends_with('Z')));
        log.stop();
        std::thread::sleep(Duration::from_millis(400));
        let topics = obs.0.lock().unwrap().clone();
        assert!(!topics.is_empty() && topics.len() <= 3, "{topics:?}");
        assert!(topics.iter().all(|t| t == TOPIC_ACTIVITY));
    }
}
