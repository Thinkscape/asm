//! SQLite store (`<data>/asm.db`). Holds settings, vault configs, hosts, pairing codes,
//! resolved request history and lease metadata. Never holds secret values: leases keep
//! sentinels and file paths only, host tokens and pairing codes are stored as SHA-256.

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
    address    TEXT NOT NULL,
    paired_at  INTEGER NOT NULL,
    last_seen  INTEGER,
    revoked_at INTEGER
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
    revoked_at  INTEGER
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
    /// Remote address observed when pairing.
    pub address: String,
    pub paired_at: i64,
    pub last_seen: Option<i64>,
    pub revoked_at: Option<i64>,
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

/// Raw `hosts` row: id, info JSON, address, paired_at, last_seen, revoked_at.
type HostRow = (String, String, String, i64, Option<i64>, Option<i64>);

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
        ))
    }

    fn host_build(t: HostRow) -> Result<HostRecord> {
        let (id, info, address, paired_at, last_seen, revoked_at) = t;
        Ok(HostRecord {
            id,
            info: serde_json::from_str(&info)?,
            address,
            paired_at,
            last_seen,
            revoked_at,
        })
    }

    pub fn insert_host(&self, h: &HostRecord, token_hash: &[u8; 32]) -> Result<()> {
        self.db().execute(
            "INSERT INTO hosts(id, token_hash, info, address, paired_at, last_seen, revoked_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            params![
                h.id,
                &token_hash[..],
                serde_json::to_string(&h.info)?,
                h.address,
                h.paired_at,
                h.last_seen
            ],
        )?;
        Ok(())
    }

    /// The non-revoked host whose token hashes to `token_hash` (compared in constant time).
    pub fn host_by_token(&self, token_hash: &[u8; 32]) -> Result<Option<HostRecord>> {
        let db = self.db();
        let row = db
            .query_row(
                "SELECT id, info, address, paired_at, last_seen, revoked_at, token_hash FROM hosts
                 WHERE token_hash = ?1 AND revoked_at IS NULL",
                [&token_hash[..]],
                |r| Ok((Self::host_from_row(r)?, r.get::<_, Vec<u8>>(6)?)),
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
                "SELECT id, info, address, paired_at, last_seen, revoked_at FROM hosts WHERE id = ?1",
                [id],
                Self::host_from_row,
            )
            .optional()?;
        t.map(Self::host_build).transpose()
    }

    pub fn list_hosts(&self) -> Result<Vec<HostRecord>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT id, info, address, paired_at, last_seen, revoked_at FROM hosts
             WHERE revoked_at IS NULL ORDER BY paired_at",
        )?;
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
            "INSERT INTO pairing_codes(id, label, secret_hash, created_at, expires_at, max_uses, uses, revoked_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, 0, NULL)",
            params![c.id, c.label, &secret_hash[..], c.created_at, c.expires_at, c.max_uses],
        )?;
        Ok(())
    }

    pub fn list_pairing_codes(&self) -> Result<Vec<PairingCodeRecord>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT id, label, created_at, expires_at, max_uses, uses, revoked_at FROM pairing_codes
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

    /// Atomically check a pairing code (hash, expiry, remaining uses, not revoked), count one
    /// use, and insert the new host. Returns false (nothing changed) when the code is rejected.
    pub fn consume_pairing_code(
        &self,
        secret_hash: &[u8; 32],
        now: i64,
        host: &HostRecord,
        token_hash: &[u8; 32],
    ) -> Result<bool> {
        let mut db = self.db();
        let tx = db.transaction()?;
        let row: Option<(String, Vec<u8>)> = tx
            .query_row(
                "SELECT id, secret_hash FROM pairing_codes
                 WHERE secret_hash = ?1 AND revoked_at IS NULL
                   AND (expires_at IS NULL OR expires_at > ?2)
                   AND (max_uses IS NULL OR uses < max_uses)",
                params![&secret_hash[..], now],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((id, stored)) = row else {
            return Ok(false);
        };
        if !asm_proto::crypto::ct_eq(&stored, secret_hash) {
            return Ok(false);
        }
        tx.execute(
            "UPDATE pairing_codes SET uses = uses + 1 WHERE id = ?1",
            [&id],
        )?;
        tx.execute(
            "INSERT INTO hosts(id, token_hash, info, address, paired_at, last_seen, revoked_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            params![
                host.id,
                &token_hash[..],
                serde_json::to_string(&host.info)?,
                host.address,
                host.paired_at,
                host.last_seen
            ],
        )?;
        tx.commit()?;
        Ok(true)
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
            address: "10.0.0.2".into(),
            paired_at: 100,
            last_seen: None,
            revoked_at: None,
        }
    }

    #[test]
    fn pairing_code_consumption_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("asm.db")).unwrap();
        let hash = [7u8; 32];
        let code = PairingCodeRecord {
            id: "c1".into(),
            label: "ci".into(),
            created_at: 100,
            expires_at: Some(1000),
            max_uses: Some(1),
            uses: 0,
            revoked_at: None,
        };
        s.insert_pairing_code(&code, &hash).unwrap();
        assert!(
            !s.consume_pairing_code(&[8u8; 32], 200, &host("h0"), &[0u8; 32])
                .unwrap()
        );
        assert!(
            s.consume_pairing_code(&hash, 200, &host("h1"), &[1u8; 32])
                .unwrap()
        );
        assert!(
            !s.consume_pairing_code(&hash, 201, &host("h2"), &[2u8; 32])
                .unwrap(),
            "used up"
        );
        assert!(s.host_by_token(&[1u8; 32]).unwrap().is_some());
        assert!(s.get_host("h2").unwrap().is_none());

        let code2 = PairingCodeRecord {
            id: "c2".into(),
            max_uses: None,
            ..code
        };
        s.insert_pairing_code(&code2, &[9u8; 32]).unwrap();
        assert!(
            !s.consume_pairing_code(&[9u8; 32], 1000, &host("h3"), &[3u8; 32])
                .unwrap(),
            "expired"
        );
        assert!(
            s.consume_pairing_code(&[9u8; 32], 999, &host("h4"), &[4u8; 32])
                .unwrap()
        );
        assert!(s.revoke_pairing_code("c2", 999).unwrap());
        assert!(
            !s.consume_pairing_code(&[9u8; 32], 999, &host("h5"), &[5u8; 32])
                .unwrap(),
            "revoked"
        );
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
