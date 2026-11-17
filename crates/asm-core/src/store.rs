//! SQLite store (`<data>/asm.db`). Holds settings, vault configs, hosts, pairing codes,
//! resolved request history, lease metadata and the activity log. Never holds secret
//! values: leases keep sentinels and file paths only, host tokens and pairing codes are
//! stored as SHA-256.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Mutex;

use asm_proto::wire::{HostInfo, LeaseMode, LeaseStatus};
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::vault::VaultConfig;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS settings(
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vaults(
    id       TEXT PRIMARY KEY,
    name     TEXT NOT NULL UNIQUE,
    config   TEXT NOT NULL,
    position INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts(
    id         TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL UNIQUE,
    info       TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT '',
    address    TEXT NOT NULL,
    paired_at  INTEGER NOT NULL,
    last_seen  INTEGER,
    revoked_at INTEGER,
    machine_hint TEXT
);
CREATE TABLE IF NOT EXISTS host_agents(
    host_id   TEXT NOT NULL,
    agent     TEXT NOT NULL,
    last_seen INTEGER NOT NULL,
    PRIMARY KEY(host_id, agent)
);
CREATE TABLE IF NOT EXISTS pairing_codes(
    id          TEXT PRIMARY KEY,
    label       TEXT NOT NULL,
    secret_hash BLOB NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER,
    max_uses    INTEGER,
    uses        INTEGER NOT NULL DEFAULT 0,
    revoked_at  INTEGER,
    networks    TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS requests(
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    host_id     TEXT,
    host_label  TEXT NOT NULL,
    summary     TEXT NOT NULL,
    status      TEXT NOT NULL,
    deny_reason TEXT,
    created_at  INTEGER NOT NULL,
    resolved_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS requests_resolved ON requests(resolved_at);
CREATE TABLE IF NOT EXISTS leases(
    id         TEXT PRIMARY KEY,
    host_id    TEXT NOT NULL,
    vault_id   TEXT NOT NULL,
    vault_name TEXT NOT NULL,
    secret_key TEXT NOT NULL,
    name       TEXT NOT NULL,
    mode       TEXT NOT NULL,
    fields     TEXT NOT NULL,
    hosts      TEXT NOT NULL,
    reason     TEXT NOT NULL,
    agent      TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS leases_secret ON leases(vault_id, secret_key);
CREATE TABLE IF NOT EXISTS secret_hosts(
    vault_id   TEXT NOT NULL,
    secret_key TEXT NOT NULL,
    pattern    TEXT NOT NULL,
    PRIMARY KEY(vault_id, secret_key, pattern)
);
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRecord {
    pub id: String,
    pub name: String,
    pub config: VaultConfig,
    pub position: i64,
}

#[derive(Debug, Clone)]
pub struct HostRecord {
    pub id: String,
    pub info: HostInfo,
    /// Friendly name chosen by the operator (the reported hostname by default).
    pub name: String,
    /// Remote address observed when pairing.
    pub address: String,
    pub paired_at: i64,
    pub last_seen: Option<i64>,
    pub revoked_at: Option<i64>,
    /// Hex hint of the host's machine id as the CLI claimed it (forgeable; display only).
    pub machine_hint: Option<String>,
}

impl HostRecord {
    /// What the UI calls this host: its friendly name, else the reported hostname.
    pub fn label(&self) -> &str {
        if self.name.is_empty() {
            &self.info.hostname
        } else {
            &self.name
        }
    }
}

#[derive(Debug, Clone)]
pub struct PairingCodeRecord {
    pub id: String,
    pub label: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub max_uses: Option<u32>,
    pub uses: u32,
    pub revoked_at: Option<i64>,
    /// Allowed peer networks (normalised CIDRs); `[]` = any address.
    pub networks: Vec<String>,
}

/// Outcome of presenting a pairing code ([`Store::consume_pairing_code`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeUse {
    /// One use counted and the host inserted (or its token rotated); the code's label.
    Paired { label: String },
    /// The host to rotate no longer holds the proven token (or was revoked); nothing changed.
    StaleProof,
    /// A valid code presented from outside its networks; nothing changed.
    WrongNetwork {
        label: String,
        networks: Vec<String>,
    },
    /// Unknown, expired, used-up or revoked; nothing changed.
    Rejected,
}

#[derive(Debug, Clone)]
pub struct HistoryRecord {
    pub id: String,
    /// `pair`, `get`, `update`, `add`
    pub kind: String,
    pub host_id: Option<String>,
    pub host_label: String,
    pub summary: String,
    /// `approved`, `denied`, `expired`, `cancelled`
    pub status: String,
    pub deny_reason: Option<String>,
    pub created_at: i64,
    pub resolved_at: i64,
}

/// One delivered field of a lease. `sentinel` is set for sentinel-substituted fields only
/// (not for raw leases and not for `username`, which is delivered in clear).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseField {
    pub field: String,
    pub sentinel: Option<String>,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct LeaseRecord {
    pub id: String,
    pub host_id: String,
    pub vault_id: String,
    pub vault_name: String,
    pub secret_key: String,
    /// Display name at approval time.
    pub name: String,
    pub mode: LeaseMode,
    pub fields: Vec<LeaseField>,
    pub hosts: Vec<String>,
    pub reason: String,
    pub agent: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

impl LeaseRecord {
    /// Status from the wall clock (`now` in Unix seconds).
    pub fn status(&self, now: i64) -> LeaseStatus {
        if self.revoked_at.is_some() {
            LeaseStatus::Revoked
        } else if self.expires_at.is_some_and(|e| e <= now) {
            LeaseStatus::Expired
        } else {
            LeaseStatus::Active
        }
    }
    pub fn is_active(&self, now: i64) -> bool {
        self.status(now) == LeaseStatus::Active
    }
}

fn mode_str(m: LeaseMode) -> &'static str {
    match m {
        LeaseMode::Sentinel => "sentinel",
        LeaseMode::Raw => "raw",
    }
}

fn parse_mode(s: &str) -> LeaseMode {
    if s == "raw" {
        LeaseMode::Raw
    } else {
        LeaseMode::Sentinel
    }
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn db(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ---- settings ----

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .db()
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    pub fn set_setting(&self, key: &str, json: &str) -> Result<()> {
        self.db().execute(
            "INSERT INTO settings(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, json],
        )?;
        Ok(())
    }

    // ---- vaults ----

    pub fn list_vaults(&self) -> Result<Vec<VaultRecord>> {
        let db = self.db();
        let mut st =
            db.prepare("SELECT id, name, config, position FROM vaults ORDER BY position, name")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, name, config, position) = row?;
            let config: VaultConfig = serde_json::from_str(&config)?;
            out.push(VaultRecord {
                id,
                name,
                config,
                position,
            });
        }
        Ok(out)
    }

    pub fn upsert_vault(&self, v: &VaultRecord) -> Result<()> {
        let config = serde_json::to_string(&v.config)?;
        self.db()
            .execute(
                "INSERT INTO vaults(id, name, config, position) VALUES(?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET name = excluded.name, config = excluded.config",
                params![v.id, v.name, config, v.position],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(f, _)
                    if f.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    CoreError::exists(format!("a vault named {:?} already exists", v.name))
                }
                e => e.into(),
            })?;
        Ok(())
    }

    pub fn delete_vault(&self, id: &str) -> Result<()> {
        let db = self.db();
        db.execute("DELETE FROM vaults WHERE id = ?1", [id])?;
        db.execute("DELETE FROM secret_hosts WHERE vault_id = ?1", [id])?;
        Ok(())
    }
}

/// Bring a database created by an earlier build up to the current schema.
fn migrate(conn: &Connection) -> Result<()> {
    let has_name = conn
        .prepare("SELECT 1 FROM pragma_table_info('hosts') WHERE name = 'name'")?
        .exists([])?;
    if !has_name {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(
            "ALTER TABLE hosts ADD COLUMN name TEXT NOT NULL DEFAULT '';
             UPDATE hosts SET name = coalesce(json_extract(info, '$.hostname'), '');",
        )?;
        tx.commit()?;
    }
    let has_networks = conn
        .prepare("SELECT 1 FROM pragma_table_info('pairing_codes') WHERE name = 'networks'")?
        .exists([])?;
    if !has_networks {
        conn.execute_batch(
            "ALTER TABLE pairing_codes ADD COLUMN networks TEXT NOT NULL DEFAULT '[]';",
        )?;
    }
    let has_hint = conn
        .prepare("SELECT 1 FROM pragma_table_info('hosts') WHERE name = 'machine_hint'")?
        .exists([])?;
    if !has_hint {
        conn.execute_batch("ALTER TABLE hosts ADD COLUMN machine_hint TEXT;")?;
    }
    let has_activity = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'activity'")?
        .exists([])?;
    if !has_activity {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(
            "CREATE TABLE activity(
                 id       INTEGER PRIMARY KEY,
                 at       TEXT NOT NULL,
                 category TEXT NOT NULL,
                 kind     TEXT NOT NULL,
                 host_id  TEXT,
                 secret   TEXT,
                 summary  TEXT NOT NULL,
                 detail   TEXT
             );
             CREATE INDEX activity_at ON activity(at);
             CREATE INDEX activity_host ON activity(host_id, id);",
        )?;
        tx.commit()?;
    }
    Ok(())
}

/// `pairing_codes.networks` (a JSON array of CIDR strings). Unreadable text yields a
/// list that matches no address, so a damaged row never widens the allow-list.
fn networks_column(text: &str) -> Vec<String> {
    serde_json::from_str(text).unwrap_or_else(|_| vec![String::from("invalid")])
}

/// A row to append to the activity log. `at` is RFC 3339 UTC (`2026-11-16T12:34:56Z`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewActivity {
    pub at: String,
    pub category: &'static str,
    pub kind: &'static str,
    pub host_id: Option<String>,
    pub secret: Option<String>,
    pub summary: String,
    /// JSON text.
    pub detail: Option<String>,
}

/// An activity row as listed; `host_label` is the host's current friendly name ("" when
/// there is no host or it is unknown).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityRecord {
    pub id: i64,
    pub at: String,
    pub category: String,
    pub kind: String,
    pub host_id: Option<String>,
    pub host_label: String,
    pub secret: Option<String>,
    pub summary: String,
    pub detail: Option<String>,
}

/// Activity list filter. Empty `categories` = all; `search` (case-insensitive for ASCII)
/// matches the summary, the secret or the host's friendly name; newest first.
#[derive(Debug, Clone, Default)]
pub struct ActivityFilter {
    pub categories: Vec<String>,
    pub host_id: Option<String>,
    pub search: String,
    pub before_id: Option<i64>,
    pub limit: u32,
}

fn insert_host_row(db: &Connection, h: &HostRecord, token_hash: &[u8; 32]) -> Result<()> {
    db.execute(
        "INSERT INTO hosts(id, token_hash, info, name, address, paired_at, last_seen, revoked_at, machine_hint)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8)",
        params![
            h.id,
            &token_hash[..],
            serde_json::to_string(&h.info)?,
            h.name,
            h.address,
            h.paired_at,
            h.last_seen,
            h.machine_hint
        ],
    )?;
    Ok(())
}

/// Give the active host `h.id` whose token hashes to `old_hash` the token `new_hash`, and
/// refresh its info, address, machine hint and last-seen time from `h` (name, pairing time
/// and leases stay). False when no such host holds that token any more.
fn rotate_host_row(
    db: &Connection,
    h: &HostRecord,
    old_hash: &[u8; 32],
    new_hash: &[u8; 32],
) -> Result<bool> {
    let stored: Option<Vec<u8>> = db
        .query_row(
            "SELECT token_hash FROM hosts WHERE id = ?1 AND revoked_at IS NULL",
            [&h.id],
            |r| r.get(0),
        )
        .optional()?;
    if !stored.is_some_and(|s| asm_proto::crypto::ct_eq(&s, old_hash)) {
        return Ok(false);
    }
    let n = db.execute(
        "UPDATE hosts SET token_hash = ?3, info = ?4, address = ?5, last_seen = ?6, machine_hint = ?7
         WHERE id = ?1 AND token_hash = ?2 AND revoked_at IS NULL",
        params![
            h.id,
            &old_hash[..],
            &new_hash[..],
            serde_json::to_string(&h.info)?,
            h.address,
            h.last_seen,
            h.machine_hint
        ],
    )?;
    Ok(n > 0)
}

/// Columns of a [`HostRow`], in order.
const HOST_COLUMNS: &str =
    "id, info, name, address, paired_at, last_seen, revoked_at, machine_hint";

/// Raw `hosts` row: id, info JSON, name, address, paired_at, last_seen, revoked_at,
/// machine_hint.
type HostRow = (
    String,
    String,
    String,
    String,
    i64,
    Option<i64>,
    Option<i64>,
    Option<String>,
);

impl Store {
    // ---- hosts ----

    fn host_from_row(r: &Row<'_>) -> rusqlite::Result<HostRow> {
        Ok((
            r.get(0)?,
            r.get(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
            r.get(5)?,
            r.get(6)?,
            r.get(7)?,
        ))
    }

    fn host_build(t: HostRow) -> Result<HostRecord> {
        let (id, info, name, address, paired_at, last_seen, revoked_at, machine_hint) = t;
        Ok(HostRecord {
            id,
            info: serde_json::from_str(&info)?,
            name,
            address,
            paired_at,
            last_seen,
            revoked_at,
            machine_hint,
        })
    }

    pub fn insert_host(&self, h: &HostRecord, token_hash: &[u8; 32]) -> Result<()> {
        insert_host_row(&self.db(), h, token_hash)
    }

    /// The active host `id` if its token hashes to `token_hash` (compared in constant time):
    /// a proof of an earlier pairing.
    pub fn host_by_proof(&self, id: &str, token_hash: &[u8; 32]) -> Result<Option<HostRecord>> {
        let db = self.db();
        let row = db
            .query_row(
                &format!(
                    "SELECT {HOST_COLUMNS}, token_hash FROM hosts WHERE id = ?1 AND revoked_at IS NULL"
                ),
                [id],
                |r| Ok((Self::host_from_row(r)?, r.get::<_, Vec<u8>>(8)?)),
            )
            .optional()?;
        match row {
            Some((t, stored)) if asm_proto::crypto::ct_eq(&stored, token_hash) => {
                Ok(Some(Self::host_build(t)?))
            }
            _ => Ok(None),
        }
    }

    /// See [`rotate_host_row`].
    pub fn rotate_host_token(
        &self,
        h: &HostRecord,
        old_hash: &[u8; 32],
        new_hash: &[u8; 32],
    ) -> Result<bool> {
        rotate_host_row(&self.db(), h, old_hash, new_hash)
    }

    /// Active hosts claiming `machine_hint`, most recently seen first.
    pub fn hosts_with_hint(&self, machine_hint: &str) -> Result<Vec<HostRecord>> {
        let db = self.db();
        let mut st = db.prepare(&format!(
            "SELECT {HOST_COLUMNS} FROM hosts WHERE machine_hint = ?1 AND revoked_at IS NULL
             ORDER BY coalesce(last_seen, paired_at) DESC, paired_at DESC"
        ))?;
        let rows = st.query_map([machine_hint], Self::host_from_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(Self::host_build(r?)?);
        }
        Ok(out)
    }

    /// The non-revoked host whose token hashes to `token_hash` (compared in constant time).
    pub fn host_by_token(&self, token_hash: &[u8; 32]) -> Result<Option<HostRecord>> {
        let db = self.db();
        let row = db
            .query_row(
                &format!(
                    "SELECT {HOST_COLUMNS}, token_hash FROM hosts
                     WHERE token_hash = ?1 AND revoked_at IS NULL"
                ),
                [&token_hash[..]],
                |r| Ok((Self::host_from_row(r)?, r.get::<_, Vec<u8>>(8)?)),
            )
            .optional()?;
        match row {
            Some((t, stored)) if asm_proto::crypto::ct_eq(&stored, token_hash) => {
                Ok(Some(Self::host_build(t)?))
            }
            _ => Ok(None),
        }
    }

    pub fn get_host(&self, id: &str) -> Result<Option<HostRecord>> {
        let db = self.db();
        let t = db
            .query_row(
                &format!("SELECT {HOST_COLUMNS} FROM hosts WHERE id = ?1"),
                [id],
                Self::host_from_row,
            )
            .optional()?;
        t.map(Self::host_build).transpose()
    }

    pub fn list_hosts(&self) -> Result<Vec<HostRecord>> {
        let db = self.db();
        let mut st = db.prepare(&format!(
            "SELECT {HOST_COLUMNS} FROM hosts WHERE revoked_at IS NULL ORDER BY paired_at"
        ))?;
        let rows = st.query_map([], Self::host_from_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(Self::host_build(r?)?);
        }
        Ok(out)
    }

    pub fn touch_host(&self, id: &str, now: i64) -> Result<()> {
        self.db().execute(
            "UPDATE hosts SET last_seen = ?2 WHERE id = ?1",
            params![id, now],
        )?;
        Ok(())
    }

    /// Returns false when the host does not exist or is revoked.
    pub fn rename_host(&self, id: &str, name: &str) -> Result<bool> {
        let n = self.db().execute(
            "UPDATE hosts SET name = ?2 WHERE id = ?1 AND revoked_at IS NULL",
            params![id, name],
        )?;
        Ok(n > 0)
    }

    /// Returns false when the host does not exist or is already revoked.
    pub fn revoke_host(&self, id: &str, now: i64) -> Result<bool> {
        let n = self.db().execute(
            "UPDATE hosts SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
            params![id, now],
        )?;
        Ok(n > 0)
    }

    pub fn upsert_agent(&self, host_id: &str, agent: &str, now: i64) -> Result<()> {
        self.db().execute(
            "INSERT INTO host_agents(host_id, agent, last_seen) VALUES(?1, ?2, ?3)
             ON CONFLICT(host_id, agent) DO UPDATE SET last_seen = excluded.last_seen",
            params![host_id, agent, now],
        )?;
        Ok(())
    }

    /// `(agent, last_seen)` of a host, most recent first.
    pub fn agents_of(&self, host_id: &str) -> Result<Vec<(String, i64)>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT agent, last_seen FROM host_agents WHERE host_id = ?1 ORDER BY last_seen DESC",
        )?;
        let rows = st.query_map([host_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    // ---- pairing codes ----

    pub fn insert_pairing_code(&self, c: &PairingCodeRecord, secret_hash: &[u8; 32]) -> Result<()> {
        self.db().execute(
            "INSERT INTO pairing_codes(id, label, secret_hash, created_at, expires_at, max_uses, uses, revoked_at, networks)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, 0, NULL, ?7)",
            params![
                c.id,
                c.label,
                &secret_hash[..],
                c.created_at,
                c.expires_at,
                c.max_uses,
                serde_json::to_string(&c.networks)?
            ],
        )?;
        Ok(())
    }

    pub fn list_pairing_codes(&self) -> Result<Vec<PairingCodeRecord>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT id, label, created_at, expires_at, max_uses, uses, revoked_at, networks FROM pairing_codes
             WHERE revoked_at IS NULL ORDER BY created_at",
        )?;
        let rows = st.query_map([], |r| {
            Ok(PairingCodeRecord {
                id: r.get(0)?,
                label: r.get(1)?,
                created_at: r.get(2)?,
                expires_at: r.get(3)?,
                max_uses: r.get(4)?,
                uses: r.get(5)?,
                revoked_at: r.get(6)?,
                networks: networks_column(&r.get::<_, String>(7)?),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn revoke_pairing_code(&self, id: &str, now: i64) -> Result<bool> {
        let n = self.db().execute(
            "UPDATE pairing_codes SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
            params![id, now],
        )?;
        Ok(n > 0)
    }

    /// Atomically check a pairing code (hash, expiry, remaining uses, not revoked, then
    /// `network_ok` on its allowed networks), count one use, and insert the new host; with
    /// `rotate_from` (the proven token hash of the existing host `host.id`) rotate that
    /// host's token instead ([`rotate_host_row`]).
    /// Nothing changes unless the answer is [`CodeUse::Paired`]; in particular a network
    /// mismatch does not use up the code.
    pub fn consume_pairing_code(
        &self,
        secret_hash: &[u8; 32],
        now: i64,
        host: &HostRecord,
        token_hash: &[u8; 32],
        rotate_from: Option<&[u8; 32]>,
        network_ok: impl FnOnce(&[String]) -> bool,
    ) -> Result<CodeUse> {
        let mut db = self.db();
        let tx = db.transaction()?;
        let row: Option<(String, Vec<u8>, String, String)> = tx
            .query_row(
                "SELECT id, secret_hash, label, networks FROM pairing_codes
                 WHERE secret_hash = ?1 AND revoked_at IS NULL
                   AND (expires_at IS NULL OR expires_at > ?2)
                   AND (max_uses IS NULL OR uses < max_uses)",
                params![&secret_hash[..], now],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((id, stored, label, networks)) = row else {
            return Ok(CodeUse::Rejected);
        };
        if !asm_proto::crypto::ct_eq(&stored, secret_hash) {
            return Ok(CodeUse::Rejected);
        }
        let networks = networks_column(&networks);
        if !network_ok(&networks) {
            return Ok(CodeUse::WrongNetwork { label, networks });
        }
        tx.execute(
            "UPDATE pairing_codes SET uses = uses + 1 WHERE id = ?1",
            [&id],
        )?;
        match rotate_from {
            Some(old) => {
                if !rotate_host_row(&tx, host, old, token_hash)? {
                    return Ok(CodeUse::StaleProof);
                }
            }
            None => insert_host_row(&tx, host, token_hash)?,
        }
        tx.commit()?;
        Ok(CodeUse::Paired { label })
    }

    // ---- request history ----

    pub fn insert_history(&self, h: &HistoryRecord) -> Result<()> {
        self.db().execute(
            "INSERT OR REPLACE INTO requests(id, kind, host_id, host_label, summary, status, deny_reason, created_at, resolved_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                h.id,
                h.kind,
                h.host_id,
                h.host_label,
                h.summary,
                h.status,
                h.deny_reason,
                h.created_at,
                h.resolved_at
            ],
        )?;
        Ok(())
    }

    pub fn recent_history(&self, limit: u32) -> Result<Vec<HistoryRecord>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT id, kind, host_id, host_label, summary, status, deny_reason, created_at, resolved_at
             FROM requests ORDER BY resolved_at DESC, rowid DESC LIMIT ?1",
        )?;
        let rows = st.query_map([limit], |r| {
            Ok(HistoryRecord {
                id: r.get(0)?,
                kind: r.get(1)?,
                host_id: r.get(2)?,
                host_label: r.get(3)?,
                summary: r.get(4)?,
                status: r.get(5)?,
                deny_reason: r.get(6)?,
                created_at: r.get(7)?,
                resolved_at: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn prune_history(&self, older_than: i64) -> Result<()> {
        self.db()
            .execute("DELETE FROM requests WHERE resolved_at < ?1", [older_than])?;
        Ok(())
    }

    // ---- leases ----

    pub fn insert_lease(&self, l: &LeaseRecord) -> Result<()> {
        self.db().execute(
            "INSERT INTO leases(id, host_id, vault_id, vault_name, secret_key, name, mode, fields, hosts,
                                reason, agent, created_at, expires_at, revoked_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                l.id,
                l.host_id,
                l.vault_id,
                l.vault_name,
                l.secret_key,
                l.name,
                mode_str(l.mode),
                serde_json::to_string(&l.fields)?,
                serde_json::to_string(&l.hosts)?,
                l.reason,
                l.agent,
                l.created_at,
                l.expires_at,
                l.revoked_at
            ],
        )?;
        Ok(())
    }

    fn query_leases(
        &self,
        filter: &str,
        args: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<LeaseRecord>> {
        let db = self.db();
        let sql = format!(
            "SELECT id, host_id, vault_id, vault_name, secret_key, name, mode, fields, hosts, reason, agent,
                    created_at, expires_at, revoked_at
             FROM leases {filter} ORDER BY created_at, rowid"
        );
        let mut st = db.prepare(&sql)?;
        let rows = st.query_map(args, |r| {
            Ok((
                (
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ),
                (
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                ),
                (
                    r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, String>(10)?,
                ),
                (
                    r.get::<_, i64>(11)?,
                    r.get::<_, Option<i64>>(12)?,
                    r.get::<_, Option<i64>>(13)?,
                ),
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (
                (id, host_id, vault_id, vault_name),
                (secret_key, name, mode),
                (fields, hosts, reason, agent),
                t,
            ) = row?;
            out.push(LeaseRecord {
                id,
                host_id,
                vault_id,
                vault_name,
                secret_key,
                name,
                mode: parse_mode(&mode),
                fields: serde_json::from_str(&fields)?,
                hosts: serde_json::from_str(&hosts)?,
                reason,
                agent,
                created_at: t.0,
                expires_at: t.1,
                revoked_at: t.2,
            });
        }
        Ok(out)
    }

    pub fn list_leases(&self) -> Result<Vec<LeaseRecord>> {
        self.query_leases("", &[])
    }

    /// Leases that are not revoked and not past expiry at `now`.
    pub fn active_leases(&self, now: i64) -> Result<Vec<LeaseRecord>> {
        self.query_leases(
            "WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?1)",
            &[&now],
        )
    }

    pub fn leases_of_host(&self, host_id: &str) -> Result<Vec<LeaseRecord>> {
        self.query_leases("WHERE host_id = ?1", &[&host_id])
    }

    pub fn get_lease(&self, id: &str) -> Result<Option<LeaseRecord>> {
        Ok(self
            .query_leases("WHERE id = ?1", &[&id])?
            .into_iter()
            .next())
    }

    /// Revoke if not yet revoked; returns true when it changed.
    pub fn revoke_lease(&self, id: &str, now: i64) -> Result<bool> {
        let n = self.db().execute(
            "UPDATE leases SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
            params![id, now],
        )?;
        Ok(n > 0)
    }
    // ---- secret hosts ----

    pub fn secret_hosts(&self, vault_id: &str, key: &str) -> Result<Vec<String>> {
        let db = self.db();
        let mut st =
            db.prepare("SELECT pattern FROM secret_hosts WHERE vault_id = ?1 AND secret_key = ?2 ORDER BY pattern")?;
        let rows = st.query_map(params![vault_id, key], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn replace_secret_hosts(
        &self,
        vault_id: &str,
        key: &str,
        patterns: &[String],
    ) -> Result<()> {
        let mut db = self.db();
        let tx = db.transaction()?;
        tx.execute(
            "DELETE FROM secret_hosts WHERE vault_id = ?1 AND secret_key = ?2",
            params![vault_id, key],
        )?;
        for p in patterns {
            tx.execute(
                "INSERT OR IGNORE INTO secret_hosts(vault_id, secret_key, pattern) VALUES(?1, ?2, ?3)",
                params![vault_id, key, p],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    // ---- activity log ----

    pub fn insert_activity(&self, rows: &[NewActivity]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut db = self.db();
        let tx = db.transaction()?;
        {
            let mut st = tx.prepare_cached(
                "INSERT INTO activity(at, category, kind, host_id, secret, summary, detail)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for r in rows {
                st.execute(params![
                    r.at, r.category, r.kind, r.host_id, r.secret, r.summary, r.detail
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn list_activity(&self, f: &ActivityFilter) -> Result<Vec<ActivityRecord>> {
        let mut sql = String::from(
            "SELECT a.id, a.at, a.category, a.kind, a.host_id,
                    coalesce(nullif(h.name, ''), json_extract(h.info, '$.hostname'), ''),
                    a.secret, a.summary, a.detail
             FROM activity a LEFT JOIN hosts h ON h.id = a.host_id
             WHERE (?1 IS NULL OR a.id < ?1)
               AND (?2 IS NULL OR a.host_id = ?2)
               AND (?3 = ''
                    OR instr(lower(a.summary), lower(?3)) > 0
                    OR instr(lower(coalesce(a.secret, '')), lower(?3)) > 0
                    OR instr(lower(coalesce(h.name, '')), lower(?3)) > 0)",
        );
        let mut args: Vec<&dyn rusqlite::ToSql> = vec![&f.before_id, &f.host_id, &f.search];
        if !f.categories.is_empty() {
            let marks: Vec<String> = (0..f.categories.len())
                .map(|i| format!("?{}", i + 5))
                .collect();
            sql.push_str(&format!(" AND a.category IN ({})", marks.join(", ")));
        }
        sql.push_str(" ORDER BY a.id DESC LIMIT ?4");
        args.push(&f.limit);
        for c in &f.categories {
            args.push(c);
        }
        let db = self.db();
        let mut st = db.prepare(&sql)?;
        let rows = st.query_map(args.as_slice(), |r| {
            Ok(ActivityRecord {
                id: r.get(0)?,
                at: r.get(1)?,
                category: r.get(2)?,
                kind: r.get(3)?,
                host_id: r.get(4)?,
                host_label: r.get(5)?,
                secret: r.get(6)?,
                summary: r.get(7)?,
                detail: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Delete rows older than `cutoff` (RFC 3339 UTC, compared as text) and all but the
    /// newest `keep` rows. Returns the number of rows deleted.
    pub fn prune_activity(&self, cutoff: &str, keep: u32) -> Result<usize> {
        let db = self.db();
        let old = db.execute("DELETE FROM activity WHERE at < ?1", [cutoff])?;
        let over = db.execute(
            "DELETE FROM activity
             WHERE id <= (SELECT id FROM activity ORDER BY id DESC LIMIT 1 OFFSET ?1)",
            [keep],
        )?;
        Ok(old + over)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(id: &str) -> HostRecord {
        HostRecord {
            id: id.into(),
            info: HostInfo {
                hostname: "box".into(),
                ..Default::default()
            },
            name: "box".into(),
            address: "10.0.0.2".into(),
            paired_at: 100,
            last_seen: None,
            revoked_at: None,
            machine_hint: None,
        }
    }

    #[test]
    fn migrates_hosts_without_name_column() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asm.db");
        {
            // The `hosts` table as created by builds before friendly names.
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE hosts(
                    id         TEXT PRIMARY KEY,
                    token_hash BLOB NOT NULL UNIQUE,
                    info       TEXT NOT NULL,
                    address    TEXT NOT NULL,
                    paired_at  INTEGER NOT NULL,
                    last_seen  INTEGER,
                    revoked_at INTEGER
                );",
            )
            .unwrap();
            let info = HostInfo {
                hostname: "old-box".into(),
                ..Default::default()
            };
            c.execute(
                "INSERT INTO hosts VALUES('h1', x'01', ?1, '10.0.0.9', 50, 60, NULL)",
                [serde_json::to_string(&info).unwrap()],
            )
            .unwrap();
        }
        let s = Store::open(&path).unwrap();
        let h = s.get_host("h1").unwrap().expect("row kept");
        assert_eq!(h.info.hostname, "old-box");
        assert_eq!(h.name, "old-box", "name backfilled from the hostname");
        assert_eq!(h.address, "10.0.0.9");
        assert_eq!((h.paired_at, h.last_seen), (50, Some(60)));
        assert!(s.rename_host("h1", "Build box").unwrap());
        assert_eq!(s.list_hosts().unwrap()[0].label(), "Build box");
        s.insert_host(&host("h2"), &[2u8; 32]).unwrap();
        assert_eq!(s.get_host("h2").unwrap().unwrap().name, "box");
        drop(s);
        // Opening again is a no-op.
        let s = Store::open(&path).unwrap();
        assert_eq!(s.list_hosts().unwrap().len(), 2);
    }

    fn activity(
        at: &str,
        category: &'static str,
        host: Option<&str>,
        summary: &str,
    ) -> NewActivity {
        NewActivity {
            at: at.into(),
            category,
            kind: "test",
            host_id: host.map(Into::into),
            secret: Some("DEMO_TOKEN".into()),
            summary: summary.into(),
            detail: Some("{\"k\":1}".into()),
        }
    }

    #[test]
    fn migrates_database_without_activity_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asm.db");
        {
            // A database from the build before the activity log (friendly names present).
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE hosts(
                    id         TEXT PRIMARY KEY,
                    token_hash BLOB NOT NULL UNIQUE,
                    info       TEXT NOT NULL,
                    name       TEXT NOT NULL DEFAULT '',
                    address    TEXT NOT NULL,
                    paired_at  INTEGER NOT NULL,
                    last_seen  INTEGER,
                    revoked_at INTEGER
                );
                INSERT INTO hosts VALUES('h1', x'01', '{\"hostname\":\"old-box\"}', 'Build box', '10.0.0.9', 50, 60, NULL);",
            )
            .unwrap();
            assert!(
                !c.prepare("SELECT 1 FROM sqlite_master WHERE name = 'activity'")
                    .unwrap()
                    .exists([])
                    .unwrap()
            );
        }
        let s = Store::open(&path).unwrap();
        s.insert_activity(&[
            activity("2026-11-16T00:00:00Z", "pairing", Some("h1"), "renamed"),
            activity("2026-11-16T00:00:01Z", "proxy", None, "proxy started"),
        ])
        .unwrap();
        let rows = s
            .list_activity(&ActivityFilter {
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].summary, "proxy started", "newest first");
        assert_eq!(rows[1].host_label, "Build box", "current friendly name");
        assert_eq!(rows[0].host_label, "");
        drop(s);
        // Opening again keeps the rows.
        let s = Store::open(&path).unwrap();
        let f = ActivityFilter {
            limit: 10,
            ..Default::default()
        };
        assert_eq!(s.list_activity(&f).unwrap().len(), 2);
    }

    #[test]
    fn activity_filters_and_paging() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("asm.db")).unwrap();
        s.insert_host(&host("h1"), &[1u8; 32]).unwrap();
        s.rename_host("h1", "Agent Box").unwrap();
        let rows: Vec<NewActivity> = (0..10)
            .map(|i| {
                let (cat, h) = if i % 2 == 0 {
                    ("requests", Some("h1"))
                } else {
                    ("proxy", None)
                };
                activity(
                    &format!("2026-11-16T00:00:{i:02}Z"),
                    cat,
                    h,
                    &format!("row {i}"),
                )
            })
            .collect();
        s.insert_activity(&rows).unwrap();
        let list = |f: ActivityFilter| -> Vec<String> {
            s.list_activity(&f)
                .unwrap()
                .into_iter()
                .map(|r| r.summary)
                .collect()
        };
        let all = list(ActivityFilter {
            limit: 3,
            ..Default::default()
        });
        assert_eq!(all, ["row 9", "row 8", "row 7"]);
        let ids: Vec<i64> = s
            .list_activity(&ActivityFilter {
                limit: 3,
                ..Default::default()
            })
            .unwrap()
            .iter()
            .map(|r| r.id)
            .collect();
        let older = list(ActivityFilter {
            before_id: Some(ids[2]),
            limit: 3,
            ..Default::default()
        });
        assert_eq!(older, ["row 6", "row 5", "row 4"]);
        let proxy = list(ActivityFilter {
            categories: vec!["proxy".into()],
            limit: 100,
            ..Default::default()
        });
        assert_eq!(proxy.len(), 5);
        let both = list(ActivityFilter {
            categories: vec!["proxy".into(), "requests".into()],
            limit: 100,
            ..Default::default()
        });
        assert_eq!(both.len(), 10);
        let by_host = list(ActivityFilter {
            host_id: Some("h1".into()),
            limit: 100,
            ..Default::default()
        });
        assert_eq!(by_host.len(), 5);
        let by_label = list(ActivityFilter {
            search: "agent box".into(),
            limit: 100,
            ..Default::default()
        });
        assert_eq!(by_label.len(), 5, "search matches the host's friendly name");
        let by_summary = list(ActivityFilter {
            search: "ROW 3".into(),
            limit: 100,
            ..Default::default()
        });
        assert_eq!(by_summary, ["row 3"]);
        let by_secret = list(ActivityFilter {
            search: "demo_tok".into(),
            limit: 100,
            ..Default::default()
        });
        assert_eq!(by_secret.len(), 10);
    }

    #[test]
    fn activity_retention() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("asm.db")).unwrap();
        let rows: Vec<NewActivity> = (0..20)
            .map(|i| {
                activity(
                    &format!("2026-10-{:02}T12:00:00Z", i + 1),
                    "proxy",
                    None,
                    &format!("row {i}"),
                )
            })
            .collect();
        s.insert_activity(&rows).unwrap();
        let f = ActivityFilter {
            limit: 100,
            ..Default::default()
        };
        // Older than the cutoff: rows 0..=4 (Oct 1–5).
        assert_eq!(s.prune_activity("2026-10-06T00:00:00Z", 100).unwrap(), 5);
        assert_eq!(s.list_activity(&f).unwrap().len(), 15);
        // Row cap: keep the newest 10.
        assert_eq!(s.prune_activity("2026-10-06T00:00:00Z", 10).unwrap(), 5);
        let left: Vec<String> = s
            .list_activity(&f)
            .unwrap()
            .into_iter()
            .map(|r| r.summary)
            .collect();
        assert_eq!(left.len(), 10);
        assert_eq!(left.first().map(String::as_str), Some("row 19"));
        assert_eq!(left.last().map(String::as_str), Some("row 10"));
        // Under both limits: nothing to do.
        assert_eq!(s.prune_activity("2026-10-06T00:00:00Z", 10).unwrap(), 0);
    }

    #[test]
    fn pairing_code_consumption_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("asm.db")).unwrap();
        let any = |_: &[String]| true;
        let hash = [7u8; 32];
        let code = PairingCodeRecord {
            id: "c1".into(),
            label: "ci".into(),
            created_at: 100,
            expires_at: Some(1000),
            max_uses: Some(1),
            uses: 0,
            revoked_at: None,
            networks: vec![],
        };
        s.insert_pairing_code(&code, &hash).unwrap();
        assert_eq!(
            s.consume_pairing_code(&[8u8; 32], 200, &host("h0"), &[0u8; 32], None, any)
                .unwrap(),
            CodeUse::Rejected
        );
        assert_eq!(
            s.consume_pairing_code(&hash, 200, &host("h1"), &[1u8; 32], None, any)
                .unwrap(),
            CodeUse::Paired { label: "ci".into() },
            "answers the code's label"
        );
        assert_eq!(
            s.consume_pairing_code(&hash, 201, &host("h2"), &[2u8; 32], None, any)
                .unwrap(),
            CodeUse::Rejected,
            "used up"
        );
        assert!(s.host_by_token(&[1u8; 32]).unwrap().is_some());
        assert!(s.get_host("h2").unwrap().is_none());

        let code2 = PairingCodeRecord {
            id: "c2".into(),
            max_uses: None,
            ..code.clone()
        };
        s.insert_pairing_code(&code2, &[9u8; 32]).unwrap();
        assert_eq!(
            s.consume_pairing_code(&[9u8; 32], 1000, &host("h3"), &[3u8; 32], None, any)
                .unwrap(),
            CodeUse::Rejected,
            "expired"
        );
        assert!(matches!(
            s.consume_pairing_code(&[9u8; 32], 999, &host("h4"), &[4u8; 32], None, any)
                .unwrap(),
            CodeUse::Paired { .. }
        ));
        assert!(s.revoke_pairing_code("c2", 999).unwrap());
        assert_eq!(
            s.consume_pairing_code(&[9u8; 32], 999, &host("h5"), &[5u8; 32], None, any)
                .unwrap(),
            CodeUse::Rejected,
            "revoked"
        );

        // A network mismatch changes nothing: the use is not counted, no host is added.
        let code3 = PairingCodeRecord {
            id: "c3".into(),
            networks: vec!["10.0.0.0/8".into()],
            ..code
        };
        s.insert_pairing_code(&code3, &[6u8; 32]).unwrap();
        let listed = s.list_pairing_codes().unwrap();
        let c3 = listed.iter().find(|c| c.id == "c3").unwrap();
        assert_eq!(c3.networks, ["10.0.0.0/8"]);
        assert_eq!(
            s.consume_pairing_code(&[6u8; 32], 200, &host("h6"), &[6u8; 32], None, |n| {
                assert_eq!(n, ["10.0.0.0/8"]);
                false
            })
            .unwrap(),
            CodeUse::WrongNetwork {
                label: "ci".into(),
                networks: vec!["10.0.0.0/8".into()]
            }
        );
        assert!(s.get_host("h6").unwrap().is_none());
        let c3 = s
            .list_pairing_codes()
            .unwrap()
            .into_iter()
            .find(|c| c.id == "c3")
            .unwrap();
        assert_eq!(c3.uses, 0);
        assert!(matches!(
            s.consume_pairing_code(&[6u8; 32], 200, &host("h7"), &[7u8; 32], None, any)
                .unwrap(),
            CodeUse::Paired { .. }
        ));

        // Rotation: the existing host keeps its id and gets the new token.
        let code4 = PairingCodeRecord {
            id: "c4".into(),
            max_uses: None,
            ..code3
        };
        s.insert_pairing_code(&code4, &[4u8; 32]).unwrap();
        let mut again = host("h7");
        again.address = "10.0.0.77".into();
        again.machine_hint = Some("ab".repeat(32));
        assert!(matches!(
            s.consume_pairing_code(&[4u8; 32], 300, &again, &[17u8; 32], Some(&[7u8; 32]), any)
                .unwrap(),
            CodeUse::Paired { .. }
        ));
        assert!(s.host_by_token(&[7u8; 32]).unwrap().is_none());
        let h7 = s.host_by_token(&[17u8; 32]).unwrap().unwrap();
        assert_eq!((h7.id.as_str(), h7.address.as_str()), ("h7", "10.0.0.77"));
        assert_eq!(h7.machine_hint, Some("ab".repeat(32)));
        // A proof that no longer holds changes nothing (no use counted).
        assert_eq!(
            s.consume_pairing_code(&[4u8; 32], 301, &again, &[18u8; 32], Some(&[7u8; 32]), any)
                .unwrap(),
            CodeUse::StaleProof
        );
        let uses = |id: &str| {
            s.list_pairing_codes()
                .unwrap()
                .into_iter()
                .find(|c| c.id == id)
                .unwrap()
                .uses
        };
        assert_eq!(uses("c4"), 1);
        assert!(s.host_by_token(&[18u8; 32]).unwrap().is_none());
    }

    #[test]
    fn proofs_rotation_and_hints() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("asm.db")).unwrap();
        let hint = "cd".repeat(32);
        let mut a = host("a");
        a.machine_hint = Some(hint.clone());
        a.last_seen = Some(10);
        let mut b = host("b");
        b.machine_hint = Some(hint.clone());
        b.last_seen = Some(20);
        s.insert_host(&a, &[1u8; 32]).unwrap();
        s.insert_host(&b, &[2u8; 32]).unwrap();
        s.insert_host(&host("c"), &[3u8; 32]).unwrap();

        assert_eq!(s.host_by_proof("a", &[1u8; 32]).unwrap().unwrap().id, "a");
        assert!(s.host_by_proof("a", &[2u8; 32]).unwrap().is_none());
        assert!(s.host_by_proof("zz", &[1u8; 32]).unwrap().is_none());
        let ids = |v: Vec<HostRecord>| v.into_iter().map(|h| h.id).collect::<Vec<_>>();
        assert_eq!(ids(s.hosts_with_hint(&hint).unwrap()), ["b", "a"]);

        a.address = "10.9.9.9".into();
        assert!(s.rotate_host_token(&a, &[1u8; 32], &[11u8; 32]).unwrap());
        assert!(!s.rotate_host_token(&a, &[1u8; 32], &[12u8; 32]).unwrap());
        let a2 = s.host_by_proof("a", &[11u8; 32]).unwrap().unwrap();
        assert_eq!((a2.address.as_str(), a2.name.as_str()), ("10.9.9.9", "box"));

        assert!(s.revoke_host("b", 30).unwrap());
        assert!(s.host_by_proof("b", &[2u8; 32]).unwrap().is_none());
        assert!(!s.rotate_host_token(&b, &[2u8; 32], &[13u8; 32]).unwrap());
        assert_eq!(ids(s.hosts_with_hint(&hint).unwrap()), ["a"]);
    }

    #[test]
    fn migrates_pairing_codes_without_networks_column() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asm.db");
        {
            // The `pairing_codes` table as created by builds before network allow-lists.
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE pairing_codes(
                    id          TEXT PRIMARY KEY,
                    label       TEXT NOT NULL,
                    secret_hash BLOB NOT NULL UNIQUE,
                    created_at  INTEGER NOT NULL,
                    expires_at  INTEGER,
                    max_uses    INTEGER,
                    uses        INTEGER NOT NULL DEFAULT 0,
                    revoked_at  INTEGER
                );
                INSERT INTO pairing_codes VALUES('c1', 'old', x'07', 100, NULL, NULL, 2, NULL);",
            )
            .unwrap();
        }
        let s = Store::open(&path).unwrap();
        let codes = s.list_pairing_codes().unwrap();
        assert_eq!(codes.len(), 1);
        assert_eq!((codes[0].label.as_str(), codes[0].uses), ("old", 2));
        assert!(
            codes[0].networks.is_empty(),
            "existing codes allow any address"
        );
        drop(s);
        // Opening again is a no-op.
        let s = Store::open(&path).unwrap();
        assert_eq!(s.list_pairing_codes().unwrap().len(), 1);
    }

    #[test]
    fn lease_status_and_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("asm.db")).unwrap();
        let l = LeaseRecord {
            id: "l1".into(),
            host_id: "h".into(),
            vault_id: "v".into(),
            vault_name: "env".into(),
            secret_key: "K".into(),
            name: "K".into(),
            mode: LeaseMode::Sentinel,
            fields: vec![LeaseField {
                field: "value".into(),
                sentinel: Some("asm_x".into()),
                path: "K".into(),
            }],
            hosts: vec!["a.com".into()],
            reason: "r".into(),
            agent: "".into(),
            created_at: 10,
            expires_at: Some(20),
            revoked_at: None,
        };
        s.insert_lease(&l).unwrap();
        assert_eq!(s.active_leases(19).unwrap().len(), 1);
        assert!(s.active_leases(20).unwrap().is_empty());
        let got = s.get_lease("l1").unwrap().unwrap();
        assert_eq!(got.status(19), LeaseStatus::Active);
        assert_eq!(got.status(20), LeaseStatus::Expired);
        assert!(s.revoke_lease("l1", 15).unwrap());
        assert!(!s.revoke_lease("l1", 16).unwrap());
        assert_eq!(
            s.get_lease("l1").unwrap().unwrap().status(15),
            LeaseStatus::Revoked
        );
        s.replace_secret_hosts("v", "K", &["b.com".into(), "a.com".into()])
            .unwrap();
        assert_eq!(s.secret_hosts("v", "K").unwrap(), vec!["a.com", "b.com"]);
    }
}
