//! SQLite store (`<data>/asm.db`). Holds settings, source configs, hosts, pairing codes,
//! resolved request history, lease metadata and the activity log. Restart state
//! containing secrets arrives as authenticated ciphertext; host tokens and pairing
//! codes are stored as SHA-256 rather than plaintext.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Mutex;

use asm_proto::generators::{
    GcloudAccessGrant, GcloudAccessRequest, GenerationGrant, GenerationRequest, SourceKind,
};
use asm_proto::wire::{HostInfo, LeaseMode, LeaseStatus, LoginScope};
use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::generator::GeneratorConfig;
use crate::manager::resume::SealedResume;
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
CREATE TABLE IF NOT EXISTS generators(
    id       TEXT PRIMARY KEY,
    name     TEXT NOT NULL UNIQUE,
    config   TEXT NOT NULL,
    revision INTEGER NOT NULL,
    position INTEGER NOT NULL,
    require_exact_scope_match INTEGER NOT NULL DEFAULT 0 CHECK (require_exact_scope_match IN (0, 1))
);
-- Preserve the exact cloud resource for cleanup even if creation was ambiguous,
-- the generator was disconnected/removed, or another attempt replaces this one.
CREATE TABLE IF NOT EXISTS gcloud_profiles(
    generator_id TEXT NOT NULL,
    account_subject TEXT NOT NULL,
    project_id TEXT NOT NULL,
    permissions TEXT NOT NULL,
    account_id TEXT NOT NULL,
    admin_email TEXT NOT NULL,
    unique_id TEXT UNIQUE,
    phase INTEGER NOT NULL DEFAULT 0 CHECK (phase BETWEEN 0 AND 4),
    superseded INTEGER NOT NULL DEFAULT 0 CHECK (superseded IN (0, 1)),
    CHECK ((phase = 0 AND unique_id IS NULL) OR (phase > 0 AND unique_id IS NOT NULL)),
    CHECK (superseded = 0 OR phase = 0),
    PRIMARY KEY(project_id, account_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS gcloud_profiles_current
    ON gcloud_profiles(generator_id, account_subject, project_id, permissions)
    WHERE superseded = 0;
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
    revoked_at INTEGER,
    source_kind TEXT NOT NULL DEFAULT 'vault',
    generation TEXT,
    generator_revision INTEGER,
    credential_expires_at INTEGER,
    approval_order INTEGER,
    credential_version INTEGER NOT NULL DEFAULT 0,
    requested_generation TEXT,
    login TEXT
);
CREATE INDEX IF NOT EXISTS leases_secret ON leases(vault_id, secret_key);
CREATE TABLE IF NOT EXISTS secret_hosts(
    vault_id   TEXT NOT NULL,
    secret_key TEXT NOT NULL,
    pattern    TEXT NOT NULL,
    PRIMARY KEY(vault_id, secret_key, pattern)
);
CREATE TABLE IF NOT EXISTS resume_identity(
    singleton   INTEGER PRIMARY KEY CHECK(singleton = 1),
    database_id BLOB NOT NULL CHECK(typeof(database_id) = 'blob' AND length(database_id) = 16),
    key_check   BLOB NOT NULL CHECK(typeof(key_check) = 'blob' AND length(key_check) = 28),
    writer_id   BLOB CHECK(writer_id IS NULL OR (typeof(writer_id) = 'blob' AND length(writer_id) = 16))
);
CREATE TABLE IF NOT EXISTS resume_entries(
    namespace TEXT NOT NULL,
    id        TEXT NOT NULL,
    sealed    BLOB NOT NULL,
    PRIMARY KEY(namespace, id)
) WITHOUT ROWID;
";

// The issued UID identifies the account even for legacy OAuth leases whose
// generator and quota project differ. Never derive it from mutable config or
// match a lease's requested claims, email, or account name.
const GCLOUD_LEASE_UID: &str = "CASE WHEN json_valid(generation) THEN
    CASE WHEN json_extract(generation, '$.provider') = 'gcloud'
        OR (json_extract(generation, '$.provider') = 'gcloud_access'
            AND json_extract(generation, '$.scope.state') = 'issued')
    THEN json_extract(generation, '$.scope.service_account_unique_id') END
END";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRecord {
    pub id: String,
    pub name: String,
    pub config: VaultConfig,
    pub position: i64,
}

/// A configured generator; credentials are stored separately in the keychain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratorRecord {
    pub id: String,
    pub name: String,
    pub config: GeneratorConfig,
    pub revision: u64,
    pub position: i64,
    pub require_exact_scope_match: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct GcloudProfileKey {
    pub generator_id: String,
    pub account_subject: String,
    pub access: GcloudAccessRequest,
}

impl GcloudProfileKey {
    fn permissions(&self) -> Result<String> {
        profile_permissions(&self.access)
    }
}

fn profile_permissions(access: &GcloudAccessRequest) -> Result<String> {
    access.validate()?;
    Ok(serde_json::to_string(&access.permissions)?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GcloudProfilePhase {
    /// No immutable ID was recorded. Never look up by this attempt's name.
    Creating,
    Created,
    ProjectBound,
    TokenCreatorBound,
    Ready,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GcloudProfileRecord {
    pub account_id: String,
    pub admin_email: String,
    pub unique_id: Option<String>,
    pub phase: GcloudProfilePhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GcloudAccountDeletion {
    None,
    Pending,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GcloudManagedAccount {
    /// Local journal row; never a substitute for checking the immutable Google UID.
    pub id: i64,
    pub key: GcloudProfileKey,
    pub profile: GcloudProfileRecord,
    pub superseded: bool,
    pub deletion: GcloudAccountDeletion,
    pub leases: Vec<LeaseRecord>,
}

pub(crate) fn gcloud_profile_email(project_id: &str, account_id: &str) -> String {
    format!("{account_id}@{project_id}.iam.gserviceaccount.com")
}

fn validate_profile_account_id(value: &str) -> Result<()> {
    if (6..=30).contains(&value.len())
        && value.starts_with("asm-")
        && value.ends_with(|ch: char| ch.is_ascii_alphanumeric())
        && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        Ok(())
    } else {
        Err(CoreError::invalid("invalid ASM Google service account name"))
    }
}

pub(crate) fn validate_profile_admin_email(value: &str) -> Result<()> {
    if value.len() <= 254
        && value.bytes().all(|ch| ch.is_ascii_graphic() && ch != b':')
        && value.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && !domain.is_empty() && !domain.contains('@')
        })
    {
        Ok(())
    } else {
        Err(CoreError::invalid("invalid verified Google account email"))
    }
}

fn profile_changed() -> CoreError {
    CoreError::vault_unavailable("Google IAM profile changed; review it again")
}

fn gcloud_profile_deleting() -> CoreError {
    CoreError::vault_unavailable("Google IAM profile deletion is pending; retry it in generator settings")
}

fn decode_gcloud_profile(
    account_id: String, admin_email: String, unique_id: Option<String>, phase: i64,
) -> Result<GcloudProfileRecord> {
    validate_profile_account_id(&account_id)?;
    validate_profile_admin_email(&admin_email)?;
    if let Some(id) = &unique_id {
        crate::generator::gcloud::validate_unique_id(id)?;
    }
    let phase = match (phase, unique_id.is_some()) {
        (0, false) => GcloudProfilePhase::Creating,
        (1, true) => GcloudProfilePhase::Created,
        (2, true) => GcloudProfilePhase::ProjectBound,
        (3, true) => GcloudProfilePhase::TokenCreatorBound,
        (4, true) => GcloudProfilePhase::Ready,
        _ => return Err(CoreError::internal("invalid stored Google IAM profile phase")),
    };
    Ok(GcloudProfileRecord { account_id, admin_email, unique_id, phase })
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub source_kind: SourceKind,
    pub generation: Option<GenerationGrant>,
    pub generator_revision: Option<u64>,
    /// Last issued provider expiry; not evidence that a live credential is cached.
    pub credential_expires_at: Option<i64>,
    pub approval_order: Option<u64>,
    /// Durable high-water mark; generated credentials never reset it after restart.
    pub credential_version: u64,
    pub requested_generation: Option<GenerationRequest>,
    /// Login grant scope (form action URL) of a single-use login sentinel lease.
    pub login: Option<LoginScope>,
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

fn parse_mode(s: &str) -> Result<LeaseMode> {
    match s {
        "raw" => Ok(LeaseMode::Raw),
        "sentinel" => Ok(LeaseMode::Sentinel),
        _ => Err(CoreError::internal("invalid persisted lease mode")),
    }
}

fn source_kind_str(kind: SourceKind) -> &'static str {
    match kind {
        SourceKind::Vault => "vault",
        SourceKind::Generator => "generator",
    }
}

fn parse_source_kind(s: &str) -> Result<SourceKind> {
    match s {
        "vault" => Ok(SourceKind::Vault),
        "generator" => Ok(SourceKind::Generator),
        _ => Err(CoreError::internal("invalid persisted lease source kind")),
    }
}

fn sqlite_u64(value: u64, label: &str) -> Result<i64> {
    i64::try_from(value).map_err(|_| CoreError::internal(format!("{label} exceeds SQLite integer range")))
}

fn positive_u64(value: i64, label: &str) -> Result<u64> {
    if value <= 0 {
        return Err(CoreError::internal(format!("invalid persisted {label}")));
    }
    Ok(value as u64)
}

/// A malformed generated row must never fall back to ordinary vault authority.
fn validate_lease_generation(lease: &LeaseRecord) -> Result<()> {
    match lease.source_kind {
        SourceKind::Vault => {
            if lease.generation.is_some()
                || lease.generator_revision.is_some()
                || lease.credential_expires_at.is_some()
                || lease.approval_order.is_some()
                || lease.credential_version != 0
                || lease.requested_generation.is_some()
            {
                return Err(CoreError::internal("vault lease contains generated metadata"));
            }
        }
        SourceKind::Generator => {
            let grant = lease
                .generation
                .as_ref()
                .ok_or_else(|| CoreError::internal("generated lease has no grant"))?;
            grant
                .validate()
                .map_err(|_| CoreError::internal("invalid generated lease grant"))?;
            if !grant.is_issued() {
                return Err(CoreError::internal("a managed Google lease must have an issued profile"));
            }
            match (grant, &lease.requested_generation) {
                // The original project and permissions are historical metadata.
                // Only the separately validated issued profile grants authority.
                (GenerationGrant::GcloudAccess(GcloudAccessGrant::Issued { .. }),
                    Some(GenerationRequest::GcloudAccess(_))) => {}
                (GenerationGrant::GcloudAccess(_), _) => {
                    return Err(CoreError::internal("managed Google lease has no original Google request"));
                }
                // Request metadata documents what the host asked for; it cannot
                // confer authority or replace the separately validated grant.
                (GenerationGrant::GithubApp(_), None | Some(GenerationRequest::GithubApp(_)))
                | (GenerationGrant::Gcloud(_), None | Some(GenerationRequest::Gcloud(_))) => {}
                _ => return Err(CoreError::internal("generated lease request does not match its provider")),
            }
            let revision = lease
                .generator_revision
                .filter(|n| *n > 0)
                .ok_or_else(|| CoreError::internal("generated lease has no generator revision"))?;
            let order = lease
                .approval_order
                .filter(|n| *n > 0)
                .ok_or_else(|| CoreError::internal("generated lease has no approval order"))?;
            if lease.credential_version == 0 {
                return Err(CoreError::internal("generated lease has no credential version"));
            }
            sqlite_u64(revision, "generator revision")?;
            sqlite_u64(order, "generator approval order")?;
            sqlite_u64(lease.credential_version, "credential version")?;
            if !lease.credential_expires_at.is_some_and(|n| n > 0) {
                return Err(CoreError::internal("generated lease has no credential expiry"));
            }
            if lease.expires_at.is_some_and(|n| n <= lease.created_at) {
                return Err(CoreError::internal("generated lease has no authorization duration"));
            }
            if let Some(request) = &lease.requested_generation {
                let mut canonical = request.clone();
                canonical
                    .canonicalize()
                    .map_err(|_| CoreError::internal("invalid generated lease request"))?;
                // Older approvals stored omitted GitHub permissions as None.
                // Preserve that historical request metadata; the separate
                // canonical grant above remains the source of lease authority.
                if let (GenerationRequest::GithubApp(stored), GenerationRequest::GithubApp(normalized)) =
                    (request, &mut canonical)
                    && stored.permissions.is_none()
                {
                    normalized.permissions = None;
                }
                if &canonical != request {
                    return Err(CoreError::internal("noncanonical generated lease request"));
                }
            }
        }
    }
    Ok(())
}

fn issued_gcloud_uid(grant: Option<&GenerationGrant>) -> Option<&str> {
    match grant? {
        GenerationGrant::Gcloud(grant) => Some(&grant.service_account_unique_id),
        GenerationGrant::GcloudAccess(GcloudAccessGrant::Issued { service_account_unique_id, .. }) => {
            Some(service_account_unique_id)
        }
        _ => None,
    }
}

fn source_name_error(name: &str) -> CoreError {
    CoreError::exists(format!("a source named {name:?} already exists"))
}

fn source_constraint_error(error: rusqlite::Error, name: &str) -> CoreError {
    match error {
        rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            source_name_error(name)
        }
        e => e.into(),
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
        // Cloud deletion cannot start until the local retirement survived commit.
        conn.pragma_update(None, "synchronous", "FULL")?;
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

    pub(crate) fn claim_resume_writer<T>(
        &self,
        fresh_id: [u8; 16],
        writer_id: &[u8; 16],
        load: impl FnOnce(&[u8; 16], Vec<u8>) -> Result<T>,
        create: impl FnOnce(&[u8; 16]) -> Result<(T, Vec<u8>)>,
    ) -> Result<([u8; 16], T)> {
        let mut db = self.db();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT database_id, key_check FROM resume_identity WHERE singleton = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (id, key) = if let Some((id, verifier)) = existing {
            let id = id
                .try_into()
                .map_err(|_| CoreError::internal("invalid restart database identity"))?;
            let key = load(&id, verifier)?;
            tx.execute(
                "UPDATE resume_identity SET writer_id = ?1 WHERE singleton = 1",
                [&writer_id[..]],
            )?;
            (id, key)
        } else {
            if tx.prepare("SELECT 1 FROM resume_entries LIMIT 1")?.exists([])? {
                return Err(CoreError::internal("restart database identity is missing"));
            }
            // Persist the create-only key first, under a fresh random ID. If the
            // process dies before commit, the DB is still empty; an unreferenced
            // keychain item is safer than a committed DB whose key never existed.
            let (key, verifier) = create(&fresh_id)?;
            tx.execute(
                "INSERT INTO resume_identity(singleton, database_id, key_check, writer_id)
                 VALUES(1, ?1, ?2, ?3)",
                params![&fresh_id[..], verifier, &writer_id[..]],
            )?;
            (fresh_id, key)
        };
        tx.commit()?;
        Ok((id, key))
    }

    pub(crate) fn release_resume_writer(&self, id: &[u8; 16]) -> Result<()> {
        self.db().execute(
            "UPDATE resume_identity SET writer_id = NULL WHERE singleton = 1 AND writer_id = ?1",
            [&id[..]],
        )?;
        Ok(())
    }

    pub(crate) fn commit_resume(&self, rows: &[SealedResume]) -> Result<()> {
        let mut db = self.db();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::apply_resume(&tx, rows)?;
        tx.commit()?;
        Ok(())
    }

    /// Must be called inside a write transaction so a new writer cannot claim the
    /// database between the fence and the caller's authority change.
    fn apply_resume(conn: &Connection, rows: &[SealedResume]) -> Result<()> {
        let Some(first) = rows.first() else {
            return Ok(());
        };
        if rows.iter().any(|r| r.writer_id != first.writer_id)
            || !conn
                .prepare_cached("SELECT 1 FROM resume_identity WHERE singleton = 1 AND writer_id = ?1")?
                .exists([&first.writer_id[..]])?
        {
            return Err(CoreError::internal("restart storage writer is no longer active"));
        }
        for row in rows {
            let (namespace, id) = row.route();
            if let Some(sealed) = &row.ciphertext {
                conn.prepare_cached(
                    "INSERT INTO resume_entries(namespace, id, sealed) VALUES(?1, ?2, ?3)
                     ON CONFLICT(namespace, id) DO UPDATE SET sealed = excluded.sealed",
                )?
                .execute(params![namespace, id, sealed])?;
            } else {
                conn.prepare_cached("DELETE FROM resume_entries WHERE namespace = ?1 AND id = ?2")?
                    .execute(params![namespace, id])?;
            }
        }
        Ok(())
    }

    pub(crate) fn get_resume(&self, namespace: &str, id: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .db()
            .prepare_cached("SELECT sealed FROM resume_entries WHERE namespace = ?1 AND id = ?2")?
            .query_row(params![namespace, id], |r| r.get(0))
            .optional()?)
    }

    pub(crate) fn list_resume(&self, namespace: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let db = self.db();
        let mut stmt = db.prepare_cached(
            "SELECT id, sealed FROM resume_entries WHERE namespace = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map([namespace], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
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

    /// Reserve decision order before provider I/O; failed decisions may leave gaps.
    pub fn reserve_generator_approval_order(&self) -> Result<u64> {
        let mut db = self.db();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let value: Option<String> = tx
            .query_row(
                "SELECT value FROM settings WHERE key = 'generator_approval_order'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let previous = match value {
            None => 0,
            Some(value) => value
                .parse::<i64>()
                .ok()
                .filter(|n| *n >= 0)
                .ok_or_else(|| CoreError::internal("invalid generator approval order"))?,
        };
        let next = previous
            .checked_add(1)
            .ok_or_else(|| CoreError::internal("generator approval order exhausted"))?;
        tx.execute(
            "INSERT INTO settings(key, value) VALUES('generator_approval_order', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [next.to_string()],
        )?;
        tx.commit()?;
        Ok(next as u64)
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
        let mut db = self.db();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if tx
            .prepare("SELECT 1 FROM generators WHERE name = ?1")?
            .exists([&v.name])?
        {
            return Err(source_name_error(&v.name));
        }
        tx.execute(
            "INSERT INTO vaults(id, name, config, position) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET name = excluded.name, config = excluded.config",
            params![v.id, v.name, config, v.position],
        )
        .map_err(|e| source_constraint_error(e, &v.name))?;
        tx.commit()?;
        Ok(())
    }

    pub fn delete_vault(&self, id: &str) -> Result<()> {
        let db = self.db();
        db.execute("DELETE FROM vaults WHERE id = ?1", [id])?;
        db.execute("DELETE FROM secret_hosts WHERE vault_id = ?1", [id])?;
        Ok(())
    }

    // ---- generators ----

    pub fn list_generators(&self) -> Result<Vec<GeneratorRecord>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT id, name, config, revision, position, require_exact_scope_match
             FROM generators ORDER BY position, name",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, bool>(5)?,
            ))
        })?;
        rows.map(|row| {
            let (id, name, config, revision, position, require_exact_scope_match) = row?;
            Ok(GeneratorRecord {
                id,
                name,
                config: serde_json::from_str(&config)?,
                revision: positive_u64(revision, "generator revision")?,
                position,
                require_exact_scope_match,
            })
        })
        .collect()
    }

    pub fn get_generator(&self, id: &str) -> Result<Option<GeneratorRecord>> {
        let db = self.db();
        let row = db
            .query_row(
                "SELECT name, config, revision, position, require_exact_scope_match FROM generators WHERE id = ?1",
                [id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, bool>(4)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(name, config, revision, position, require_exact_scope_match)| {
            Ok(GeneratorRecord {
                id: id.into(),
                name,
                config: serde_json::from_str(&config)?,
                revision: positive_u64(revision, "generator revision")?,
                position,
                require_exact_scope_match,
            })
        })
        .transpose()
    }

    pub fn upsert_generator(&self, g: &GeneratorRecord) -> Result<()> {
        if g.revision == 0 {
            return Err(CoreError::invalid("generator revision must be positive"));
        }
        match &g.config {
            GeneratorConfig::GithubApp(config) => config.validate()?,
            GeneratorConfig::GcloudConnection(config) => config.validate()?,
            GeneratorConfig::Gcloud(_) => {}
        }
        let revision = sqlite_u64(g.revision, "generator revision")?;
        let config = serde_json::to_string(&g.config)?;
        let mut db = self.db();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if tx
            .prepare("SELECT 1 FROM vaults WHERE name = ?1")?
            .exists([&g.name])?
        {
            return Err(source_name_error(&g.name));
        }
        tx.execute(
            "INSERT INTO generators(id, name, config, revision, position, require_exact_scope_match)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET name = excluded.name, config = excluded.config,
                                          revision = excluded.revision,
                                          require_exact_scope_match = excluded.require_exact_scope_match",
            params![g.id, g.name, config, revision, g.position, g.require_exact_scope_match],
        )
        .map_err(|e| source_constraint_error(e, &g.name))?;
        tx.commit()?;
        Ok(())
    }

    pub fn delete_generator(&self, id: &str) -> Result<()> {
        let mut db = self.db();
        let tx = db.transaction()?;
        tx.execute("DELETE FROM generators WHERE id = ?1", [id])?;
        tx.execute("DELETE FROM secret_hosts WHERE vault_id = ?1", [id])?;
        tx.commit()?;
        Ok(())
    }
}

impl Store {
    pub(crate) fn gcloud_profile(&self, key: &GcloudProfileKey) -> Result<Option<GcloudProfileRecord>> {
        self.gcloud_profile_for(&key.generator_id, &key.account_subject, &key.access)
    }

    pub(crate) fn gcloud_profile_for(
        &self, generator_id: &str, account_subject: &str, access: &GcloudAccessRequest,
    ) -> Result<Option<GcloudProfileRecord>> {
        let permissions = profile_permissions(access)?;
        let row = self.db().query_row(
            "SELECT account_id, admin_email, unique_id, phase, deletion_state FROM gcloud_profiles
             WHERE generator_id = ?1 AND account_subject = ?2 AND project_id = ?3
                 AND permissions = ?4 AND superseded = 0 AND deletion_state != 2",
            params![generator_id, account_subject, access.project_id, permissions],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get::<_, i64>(4)?)),
        ).optional()?;
        match row {
            None => Ok(None),
            Some((account_id, admin_email, unique_id, phase, 0)) => {
                decode_gcloud_profile(account_id, admin_email, unique_id, phase).map(Some)
            }
            Some(_) => Err(gcloud_profile_deleting()),
        }
    }

    pub(crate) fn has_recorded_gcloud_accounts(&self) -> Result<bool> {
        Ok(self.db().prepare_cached("SELECT EXISTS(SELECT 1 FROM gcloud_profiles)")?
            .query_row([], |row| row.get(0))?)
    }

    pub(crate) fn list_gcloud_managed_accounts(&self) -> Result<Vec<GcloudManagedAccount>> {
        let db = self.db();
        let tx = db.unchecked_transaction()?;
        let accounts = Self::query_gcloud_managed_accounts(&tx, "", &[])?;
        tx.commit()?;
        Ok(accounts)
    }

    pub(crate) fn gcloud_managed_account(&self, id: i64) -> Result<Option<GcloudManagedAccount>> {
        let db = self.db();
        let tx = db.unchecked_transaction()?;
        let account = Self::gcloud_managed_account_with(&tx, id)?;
        tx.commit()?;
        Ok(account)
    }

    fn gcloud_managed_account_with(db: &Connection, id: i64) -> Result<Option<GcloudManagedAccount>> {
        Ok(Self::query_gcloud_managed_accounts(db, "WHERE rowid = ?1", &[&id])?.pop())
    }

    fn query_gcloud_managed_accounts(
        db: &Connection, filter: &str, args: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<GcloudManagedAccount>> {
        let sql = format!(
            "SELECT rowid, generator_id, account_subject, project_id, permissions, account_id,
                    admin_email, unique_id, phase, superseded, deletion_state
             FROM gcloud_profiles {filter} ORDER BY project_id, account_id"
        );
        let mut stmt = db.prepare(&sql)?;
        let mut rows = stmt.query(args)?;
        let mut accounts = Vec::new();
        while let Some(row) = rows.next()? {
            let access = GcloudAccessRequest {
                project_id: row.get(3)?,
                permissions: serde_json::from_str(&row.get::<_, String>(4)?)?,
            };
            access.validate()?;
            let profile = decode_gcloud_profile(row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?)?;
            let superseded: bool = row.get(9)?;
            let deletion = match row.get::<_, i64>(10)? {
                0 => GcloudAccountDeletion::None,
                1 => GcloudAccountDeletion::Pending,
                2 => GcloudAccountDeletion::Deleted,
                _ => return Err(CoreError::internal("invalid stored Google IAM deletion state")),
            };
            let leases = if let Some(uid) = &profile.unique_id {
                let filter = format!("WHERE source_kind = 'generator' AND ({GCLOUD_LEASE_UID}) = ?1");
                Self::query_leases_with(db, &filter, &[uid])?
            } else {
                Vec::new()
            };
            accounts.push(GcloudManagedAccount {
                id: row.get(0)?,
                key: GcloudProfileKey { generator_id: row.get(1)?, account_subject: row.get(2)?, access },
                profile,
                superseded,
                deletion,
                leases,
            });
        }
        Ok(accounts)
    }

    /// A pending deletion and the removal of all its local leases become visible
    /// together, before any cloud write. A failed cloud call never rolls this back.
    pub(crate) fn begin_gcloud_account_deletion(
        &self, expected: &GcloudManagedAccount, generator_revision: u64,
    ) -> Result<GcloudManagedAccount> {
        let mut db = self.db();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut current = Self::gcloud_managed_account_with(&tx, expected.id)?.ok_or_else(profile_changed)?;
        if &current != expected || current.deletion == GcloudAccountDeletion::Deleted {
            return Err(profile_changed());
        }
        if current.superseded || current.profile.unique_id.is_none() {
            return Err(CoreError::invalid("Google IAM profile has no verified account identity"));
        }
        let config = tx.query_row(
            "SELECT config FROM generators WHERE id = ?1 AND revision = ?2",
            params![current.key.generator_id, sqlite_u64(generator_revision, "generator revision")?],
            |row| row.get::<_, String>(0),
        ).optional()?.ok_or_else(profile_changed)?;
        let GeneratorConfig::GcloudConnection(config) = serde_json::from_str(&config)? else {
            return Err(profile_changed());
        };
        if config.account_subject != current.key.account_subject || config.account_email != current.profile.admin_email {
            return Err(profile_changed());
        }

        if current.deletion == GcloudAccountDeletion::None {
            if tx.execute("UPDATE gcloud_profiles SET deletion_state = 1 WHERE rowid = ?1", [current.id])? != 1 {
                return Err(profile_changed());
            }
        }
        {
            let mut delete = tx.prepare("DELETE FROM leases WHERE id = ?1")?;
            for lease in &current.leases {
                if delete.execute([&lease.id])? != 1 {
                    return Err(profile_changed());
                }
            }
        }
        tx.commit()?;
        current.deletion = GcloudAccountDeletion::Pending;
        current.leases = Vec::new();
        Ok(current)
    }

    /// The cloud account is confirmed gone. Keep the journal and its unique
    /// immutable UID reserved, but allow a fresh account for the same claims.
    pub(crate) fn finish_gcloud_account_deletion(&self, expected_pending: &GcloudManagedAccount) -> Result<()> {
        if expected_pending.deletion != GcloudAccountDeletion::Pending || !expected_pending.leases.is_empty() {
            return Err(profile_changed());
        }
        let mut db = self.db();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut current = Self::gcloud_managed_account_with(&tx, expected_pending.id)?.ok_or_else(profile_changed)?;
        let deletion = current.deletion;
        current.deletion = GcloudAccountDeletion::Pending;
        if &current != expected_pending || deletion == GcloudAccountDeletion::None {
            return Err(profile_changed());
        }
        if deletion == GcloudAccountDeletion::Pending {
            if tx.execute("UPDATE gcloud_profiles SET deletion_state = 2 WHERE rowid = ?1", [current.id])? != 1 {
                return Err(profile_changed());
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn gcloud_account_is_retired(&self, unique_id: &str) -> Result<bool> {
        Self::gcloud_account_is_retired_with(&self.db(), unique_id)
    }

    fn gcloud_account_is_retired_with(db: &Connection, unique_id: &str) -> Result<bool> {
        Ok(db.prepare_cached("SELECT 1 FROM gcloud_profiles WHERE unique_id = ?1 AND deletion_state != 0")?
            .exists([unique_id])?)
    }

    pub(crate) fn gcloud_profile_cleanup_resources(
        &self, generator_id: &str, account_subject: &str, admin_email: &str,
    ) -> Result<Vec<(GcloudAccessRequest, String, Option<String>)>> {
        let db = self.db();
        let mut stmt = db.prepare(
            "SELECT project_id, permissions, account_id, unique_id FROM gcloud_profiles
             WHERE generator_id = ?1 AND account_subject = ?2 AND admin_email = ?3 AND deletion_state != 2
             ORDER BY project_id, account_id",
        )?;
        let rows = stmt.query_map(params![generator_id, account_subject, admin_email], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, Option<String>>(3)?))
        })?;
        rows.map(|row| {
            let (project_id, permissions, account_id, unique_id) = row?;
            let access = GcloudAccessRequest { project_id, permissions: serde_json::from_str(&permissions)? };
            access.validate()?;
            validate_profile_account_id(&account_id)?;
            if let Some(id) = &unique_id {
                crate::generator::gcloud::validate_unique_id(id)?;
            }
            Ok((access, account_id, unique_id))
        }).collect()
    }

    /// Record the reviewed name before calling Google. An ambiguous attempt can be
    /// replaced only by explicitly naming it; its tombstone prevents name reuse.
    pub(crate) fn begin_gcloud_profile(
        &self, key: &GcloudProfileKey, account_id: &str, admin_email: &str,
        superseded_account_id: Option<&str>,
    ) -> Result<()> {
        validate_profile_account_id(account_id)?;
        validate_profile_admin_email(admin_email)?;
        let permissions = key.permissions()?;
        let mut db = self.db();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(superseded) = superseded_account_id {
            let changed = tx.execute(
                "UPDATE gcloud_profiles SET superseded = 1
                 WHERE generator_id = ?1 AND account_subject = ?2 AND project_id = ?3
                     AND permissions = ?4 AND account_id = ?5 AND superseded = 0 AND phase = 0
                     AND deletion_state = 0",
                params![key.generator_id, key.account_subject, key.access.project_id, permissions, superseded],
            )?;
            if changed != 1 {
                return Err(profile_changed());
            }
        }
        tx.execute(
            "INSERT INTO gcloud_profiles(generator_id, account_subject, project_id, permissions, account_id, admin_email)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![key.generator_id, key.account_subject, key.access.project_id, permissions, account_id, admin_email],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn record_gcloud_profile_identity(
        &self, key: &GcloudProfileKey, account_id: &str, unique_id: &str,
    ) -> Result<()> {
        self.advance_gcloud_profile(key, account_id, unique_id, 0)
    }

    pub(crate) fn mark_gcloud_profile_project_bound(
        &self, key: &GcloudProfileKey, account_id: &str, unique_id: &str,
    ) -> Result<()> {
        self.advance_gcloud_profile(key, account_id, unique_id, 1)
    }

    pub(crate) fn mark_gcloud_profile_token_creator_bound(
        &self, key: &GcloudProfileKey, account_id: &str, unique_id: &str,
    ) -> Result<()> {
        self.advance_gcloud_profile(key, account_id, unique_id, 2)
    }

    pub(crate) fn mark_gcloud_profile_ready(
        &self, key: &GcloudProfileKey, account_id: &str, unique_id: &str,
    ) -> Result<()> {
        self.advance_gcloud_profile(key, account_id, unique_id, 3)
    }

    // Every step is a compare-and-swap on the tuple and exact resource. The unique
    // constraint also stops one immutable identity backing two different claims.
    fn advance_gcloud_profile(
        &self, key: &GcloudProfileKey, account_id: &str, unique_id: &str, prior: i64,
    ) -> Result<()> {
        crate::generator::gcloud::validate_unique_id(unique_id)?;
        let permissions = key.permissions()?;
        let changed = self.db().execute(
            "UPDATE gcloud_profiles SET unique_id = ?6, phase = phase + 1
             WHERE generator_id = ?1 AND account_subject = ?2 AND project_id = ?3
                 AND permissions = ?4 AND account_id = ?5 AND phase = ?7 AND superseded = 0
                 AND deletion_state = 0
                 AND ((?7 = 0 AND unique_id IS NULL) OR unique_id = ?6)",
            params![key.generator_id, key.account_subject, key.access.project_id, permissions, account_id, unique_id, prior],
        )?;
        if changed != 1 {
            return Err(profile_changed());
        }
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
                 id         INTEGER PRIMARY KEY,
                 at         TEXT NOT NULL,
                 category   TEXT NOT NULL,
                 kind       TEXT NOT NULL,
                 host_id    TEXT,
                 secret     TEXT,
                 summary    TEXT NOT NULL,
                 detail     TEXT,
                 request_id TEXT
             );
             CREATE INDEX activity_at ON activity(at);
             CREATE INDEX activity_host ON activity(host_id, id);
             CREATE INDEX activity_request ON activity(request_id) WHERE request_id IS NOT NULL;",
        )?;
        tx.commit()?;
    }
    let has_request_id = conn
        .prepare("SELECT 1 FROM pragma_table_info('activity') WHERE name = 'request_id'")?
        .exists([])?;
    if !has_request_id {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(
            "ALTER TABLE activity ADD COLUMN request_id TEXT;
             UPDATE activity SET request_id = json_extract(detail, '$.request_id')
              WHERE detail IS NOT NULL AND json_valid(detail);
             CREATE INDEX activity_request ON activity(request_id) WHERE request_id IS NOT NULL;",
        )?;
        tx.commit()?;
    }
    // Keep each column independently discoverable for interrupted/partial upgrades.
    for (name, definition) in [
        ("source_kind", "TEXT NOT NULL DEFAULT 'vault'"),
        ("generation", "TEXT"),
        ("generator_revision", "INTEGER"),
        ("credential_expires_at", "INTEGER"),
        ("approval_order", "INTEGER"),
        ("credential_version", "INTEGER NOT NULL DEFAULT 0"),
        ("requested_generation", "TEXT"),
        ("login", "TEXT"),
    ] {
        let exists = conn
            .prepare("SELECT 1 FROM pragma_table_info('leases') WHERE name = ?1")?
            .exists([name])?;
        if !exists {
            conn.execute_batch(&format!("ALTER TABLE leases ADD COLUMN {name} {definition};"))?;
        }
    }
    // Atomically keep in-progress deletions in the uniqueness constraint while
    // allowing a completed tombstone and a new account to share reviewed claims.
    let has_deletion_state = |db: &Connection| -> rusqlite::Result<bool> {
        db.prepare("SELECT 1 FROM pragma_table_info('gcloud_profiles') WHERE name = 'deletion_state'")?
            .exists([])
    };
    if !has_deletion_state(conn)? {
        let tx = rusqlite::Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
        if !has_deletion_state(&tx)? {
            tx.execute_batch(
                "ALTER TABLE gcloud_profiles ADD COLUMN deletion_state INTEGER NOT NULL DEFAULT 0
                    CHECK (deletion_state IN (0, 1, 2))
                    CHECK (deletion_state = 0 OR (unique_id IS NOT NULL AND superseded = 0));
                 DROP INDEX gcloud_profiles_current;
                 CREATE UNIQUE INDEX gcloud_profiles_current
                     ON gcloud_profiles(generator_id, account_subject, project_id, permissions)
                     WHERE superseded = 0 AND deletion_state != 2;",
            )?;
            tx.execute_batch(&format!(
                "CREATE INDEX leases_gcloud_uid ON leases (({GCLOUD_LEASE_UID}))
                 WHERE source_kind = 'generator';",
            ))?;
        }
        tx.commit()?;
    }
    let has_scope_policy = |db: &Connection| -> rusqlite::Result<bool> {
        db.prepare("SELECT 1 FROM pragma_table_info('generators') WHERE name = 'require_exact_scope_match'")?
            .exists([])
    };
    if !has_scope_policy(conn)? {
        let tx = rusqlite::Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
        if !has_scope_policy(&tx)? {
            tx.execute_batch("ALTER TABLE generators ADD COLUMN require_exact_scope_match
                INTEGER NOT NULL DEFAULT 0 CHECK (require_exact_scope_match IN (0, 1));")?;
        }
        tx.commit()?;
    }
    // A former one-installation config already records both copies of the ID.
    // Migrate only matching IDs; leave invalid rows unreadable rather than
    // granting authority to either ID. Do not touch revisions or leases.
    conn.execute_batch(
        "UPDATE generators
         SET config = json_remove(
             json_set(config, '$.installations', json_array(json_extract(config, '$.ceiling'))),
             '$.installation_id', '$.ceiling')
         WHERE CASE WHEN json_valid(config) THEN
             json_extract(config, '$.type') = 'github_app'
             AND json_type(config, '$.installations') IS NULL
             AND json_type(config, '$.installation_id') = 'integer'
             AND json_type(config, '$.ceiling.installation_id') = 'integer'
             AND (config -> '$.installation_id') = (config -> '$.ceiling.installation_id')
         ELSE 0 END;",
    )?;
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
    /// The request this row belongs to (pairing and secret requests), for
    /// [`Store::activity_row_for_request`].
    pub request_id: Option<String>,
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

    pub(crate) fn insert_host_with_request(
        &self, host: &HostRecord, hash: &[u8; 32], row: &SealedResume, history: &HistoryRecord,
    ) -> Result<()> {
        let mut db = self.db();
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        insert_host_row(&tx, host, hash)?;
        Self::apply_resume(&tx, std::slice::from_ref(row))?;
        Self::insert_history_with(&tx, history)?;
        tx.commit()?;
        Ok(())
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

    pub(crate) fn rotate_host_token_with_request(
        &self, host: &HostRecord, old_hash: &[u8; 32], new_hash: &[u8; 32],
        row: &SealedResume, history: &HistoryRecord,
    ) -> Result<bool> {
        let mut db = self.db();
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if !rotate_host_row(&tx, host, old_hash, new_hash)? {
            return Ok(false);
        }
        Self::apply_resume(&tx, std::slice::from_ref(row))?;
        Self::insert_history_with(&tx, history)?;
        tx.commit()?;
        Ok(true)
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

    /// `(host id, SHA-256 of its bearer token)` of every non-revoked host.
    pub fn active_host_token_hashes(&self) -> Result<Vec<(String, [u8; 32])>> {
        let db = self.db();
        let mut st =
            db.prepare("SELECT id, token_hash FROM hosts WHERE revoked_at IS NULL ORDER BY paired_at")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut out = Vec::new();
        for r in rows {
            let (id, hash) = r?;
            let hash: [u8; 32] = hash
                .try_into()
                .map_err(|_| CoreError::internal("invalid persisted host token hash"))?;
            out.push((id, hash));
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
        Self::insert_history_with(&self.db(), h)
    }

    pub(crate) fn commit_request_book(&self, rows: &[SealedResume], history: Option<&HistoryRecord>) -> Result<()> {
        let mut db = self.db();
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        Self::apply_resume(&tx, rows)?;
        if let Some(history) = history {
            Self::insert_history_with(&tx, history)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn insert_history_with(conn: &Connection, h: &HistoryRecord) -> Result<()> {
        conn.execute(
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
        Self::insert_lease_with(&self.db(), l)
    }

    pub(crate) fn insert_lease_with_request(
        &self,
        lease: &LeaseRecord,
        rows: &[SealedResume],
        history: &HistoryRecord,
    ) -> Result<()> {
        let mut db = self.db();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::apply_resume(&tx, rows)?;
        Self::insert_lease_with(&tx, lease)?;
        Self::insert_history_with(&tx, history)?;
        tx.commit()?;
        Ok(())
    }

    fn insert_lease_with(conn: &Connection, l: &LeaseRecord) -> Result<()> {
        validate_lease_generation(l)?;
        let inserted = conn.execute(
            "INSERT INTO leases(id, host_id, vault_id, vault_name, secret_key, name, mode, fields, hosts,
                                reason, agent, created_at, expires_at, revoked_at, source_kind, generation,
                                generator_revision, credential_expires_at, approval_order, credential_version,
                                requested_generation, login)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                    ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?23
             WHERE NOT EXISTS (
                 SELECT 1 FROM gcloud_profiles WHERE unique_id = ?22 AND deletion_state != 0
             )",
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
                l.revoked_at,
                source_kind_str(l.source_kind),
                l.generation.as_ref().map(serde_json::to_string).transpose()?,
                l.generator_revision.map(|n| sqlite_u64(n, "generator revision")).transpose()?,
                l.credential_expires_at,
                l.approval_order.map(|n| sqlite_u64(n, "generator approval order")).transpose()?,
                sqlite_u64(l.credential_version, "credential version")?,
                l.requested_generation.as_ref().map(serde_json::to_string).transpose()?,
                issued_gcloud_uid(l.generation.as_ref()),
                l.login.as_ref().map(serde_json::to_string).transpose()?,
            ],
        )?;
        if inserted != 1 {
            return Err(CoreError::vault_unavailable("Google service account is retired"));
        }
        Ok(())
    }

    fn query_leases(
        &self,
        filter: &str,
        args: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<LeaseRecord>> {
        Self::query_leases_with(&self.db(), filter, args)
    }

    fn query_leases_with(
        db: &Connection,
        filter: &str,
        args: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<LeaseRecord>> {
        let sql = format!(
            "SELECT id, host_id, vault_id, vault_name, secret_key, name, mode, fields, hosts, reason, agent,
                    created_at, expires_at, revoked_at, source_kind, generation, generator_revision,
                    credential_expires_at, approval_order, credential_version, requested_generation, login
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
                (
                    r.get::<_, String>(14)?,
                    r.get::<_, Option<String>>(15)?,
                    r.get::<_, Option<i64>>(16)?,
                    r.get::<_, Option<i64>>(17)?,
                    r.get::<_, Option<i64>>(18)?,
                    r.get::<_, i64>(19)?,
                    r.get::<_, Option<String>>(20)?,
                    r.get::<_, Option<String>>(21)?,
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
                (source_kind, generation, generator_revision, credential_expires_at, approval_order,
                 credential_version, requested_generation, login),
            ) = row?;
            let lease = LeaseRecord {
                id,
                host_id,
                vault_id,
                vault_name,
                secret_key,
                name,
                mode: parse_mode(&mode)?,
                fields: serde_json::from_str(&fields)?,
                hosts: serde_json::from_str(&hosts)?,
                reason,
                agent,
                created_at: t.0,
                expires_at: t.1,
                revoked_at: t.2,
                source_kind: parse_source_kind(&source_kind)?,
                generation: generation.map(|s| serde_json::from_str(&s)).transpose()?,
                generator_revision: generator_revision
                    .map(|n| positive_u64(n, "generator revision")).transpose()?,
                credential_expires_at,
                approval_order: approval_order
                    .map(|n| positive_u64(n, "generator approval order")).transpose()?,
                credential_version: u64::try_from(credential_version)
                    .map_err(|_| CoreError::internal("invalid persisted credential version"))?,
                requested_generation: requested_generation
                    .map(|s| serde_json::from_str(&s)).transpose()?,
                login: login.map(|s| serde_json::from_str(&s)).transpose()?,
            };
            validate_lease_generation(&lease)?;
            out.push(lease);
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

    /// Include ended leases: exact matching honors the newest decision even after it ends.
    pub(crate) fn generated_reuse_candidates(&self, host_id: &str, name: &str) -> Result<Vec<LeaseRecord>> {
        self.query_leases("WHERE host_id = ?1 AND name = ?2 AND source_kind = 'generator' AND mode = 'raw'",
            &[&host_id, &name])
    }

    pub fn get_lease(&self, id: &str) -> Result<Option<LeaseRecord>> {
        Ok(self
            .query_leases("WHERE id = ?1", &[&id])?
            .into_iter()
            .next())
    }

    /// Commit the next credential's metadata before publishing it to any live cache.
    /// The caller holds generated-authorization ownership and checks the deadline.
    /// A stale expected version cannot overwrite a newer credential or reset its mark.
    pub fn update_generated_credential(
        &self,
        id: &str,
        expected_version: u64,
        credential_expires_at: i64,
    ) -> Result<u64> {
        self.update_generated_credential_with_resume(id, expected_version, credential_expires_at, &[])
    }

    pub(crate) fn update_generated_credential_with_resume(
        &self,
        id: &str,
        expected_version: u64,
        credential_expires_at: i64,
        rows: &[SealedResume],
    ) -> Result<u64> {
        if credential_expires_at <= 0 {
            return Err(CoreError::invalid("credential expiry must be positive"));
        }
        let mut db = self.db();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let lease = Self::query_leases_with(&tx, "WHERE id = ?1", &[&id])?
            .into_iter()
            .next()
            .ok_or_else(|| CoreError::not_found("lease not found"))?;
        if lease.source_kind != SourceKind::Generator {
            return Err(CoreError::invalid("lease is not generated"));
        }
        if lease.revoked_at.is_some() {
            return Err(CoreError::invalid("lease is revoked"));
        }
        if let Some(uid) = issued_gcloud_uid(lease.generation.as_ref())
            && Self::gcloud_account_is_retired_with(&tx, uid)?
        {
            return Err(CoreError::vault_unavailable("Google service account is retired"));
        }
        if expected_version != lease.credential_version {
            return Err(CoreError::invalid("credential version changed"));
        }
        let next = expected_version
            .checked_add(1)
            .ok_or_else(|| CoreError::internal("credential version exhausted"))?;
        let next_sql = sqlite_u64(next, "credential version")?;
        tx.execute(
            "UPDATE leases SET credential_version = ?2, credential_expires_at = ?3
             WHERE id = ?1 AND credential_version = ?4 AND source_kind = 'generator'
               AND revoked_at IS NULL",
            params![id, next_sql, credential_expires_at, sqlite_u64(expected_version, "credential version")?],
        )?;
        Self::apply_resume(&tx, rows)?;
        tx.commit()?;
        Ok(next)
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
                "INSERT INTO activity(at, category, kind, host_id, secret, summary, detail, request_id)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for r in rows {
                st.execute(params![
                    r.at,
                    r.category,
                    r.kind,
                    r.host_id,
                    r.secret,
                    r.summary,
                    r.detail,
                    r.request_id
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

    /// Id of the row that records how a request ended (`approved`, `reused`, `denied`,
    /// `failed`, `expired`, `cancelled`); the newest such row when there are several.
    pub fn activity_row_for_request(&self, request_id: &str) -> Result<Option<i64>> {
        Ok(self
            .db()
            .query_row(
                "SELECT id FROM activity
                 WHERE request_id = ?1
                   AND category IN ('requests', 'pairing')
                   AND kind IN ('approved', 'reused', 'denied', 'failed', 'expired', 'cancelled')
                 ORDER BY id DESC LIMIT 1",
                [request_id],
                |r| r.get(0),
            )
            .optional()?)
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
#[path = "store_gcloud_profiles_tests.rs"]
mod gcloud_profile_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use asm_proto::generators::{
        GithubGrant, GithubPermission, GithubRepository, GithubScopeRequest,
    };

    fn github_grant() -> GithubGrant {
        GithubGrant {
            installation_id: 42,
            repositories: vec![GithubRepository {
                id: 7,
                full_name: "acme/web".into(),
            }],
            permissions: [
                ("contents".into(), GithubPermission::Read),
                ("metadata".into(), GithubPermission::Read),
            ]
            .into(),
        }
    }

    fn generator(id: &str, name: &str, position: i64) -> GeneratorRecord {
        GeneratorRecord {
            id: id.into(),
            name: name.into(),
            config: GeneratorConfig::GithubApp(crate::generator::GithubAppConfig {
                client_id: "Iv1.fixture".into(),
                installations: vec![github_grant()],
            }),
            revision: 1,
            position,
            require_exact_scope_match: false,
        }
    }

    fn vault(id: &str, name: &str) -> VaultRecord {
        VaultRecord {
            id: id.into(),
            name: name.into(),
            config: VaultConfig::Keychain,
            position: 0,
        }
    }

    fn generated_lease(id: &str) -> LeaseRecord {
        LeaseRecord {
            id: id.into(),
            host_id: "host".into(),
            vault_id: "generator".into(),
            vault_name: "release-bot".into(),
            secret_key: "token".into(),
            name: "GH_TOKEN".into(),
            mode: LeaseMode::Raw,
            fields: vec![LeaseField {
                field: "value".into(),
                sentinel: None,
                path: "GH_TOKEN".into(),
            }],
            hosts: vec![],
            reason: "Read acme/web".into(),
            agent: "builder".into(),
            created_at: 100,
            expires_at: Some(43_300),
            revoked_at: None,
            source_kind: SourceKind::Generator,
            generation: Some(GenerationGrant::GithubApp(github_grant())),
            generator_revision: Some(1),
            credential_expires_at: Some(3_700),
            approval_order: Some(1),
            credential_version: 1,
            requested_generation: Some(GenerationRequest::GithubApp(GithubScopeRequest {
                repositories: Some(vec!["acme/web".into()]),
                permissions: Some([("metadata".into(), GithubPermission::Read)].into()),
            })),
            login: None,
        }
    }

    #[test]
    fn scope_policy_upgrade_defaults_to_relaxed_and_preserves_strict_edits_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asm.db");
        let mut record = generator("generator", "release-bot", 3);
        let lease = generated_lease("before-upgrade");
        {
            let store = Store::open(&path).unwrap();
            store.upsert_generator(&record).unwrap();
            store.insert_lease(&lease).unwrap();
            store.db().execute_batch("ALTER TABLE generators DROP COLUMN require_exact_scope_match;").unwrap();
        }
        {
            let upgraded = Store::open(&path).unwrap();
            assert_eq!(upgraded.get_generator(&record.id).unwrap().as_ref(), Some(&record));
            record.require_exact_scope_match = true;
            upgraded.upsert_generator(&record).unwrap();
        }
        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.list_generators().unwrap(), [record]);
        assert_eq!(reopened.get_lease(&lease.id).unwrap().as_ref(), Some(&lease));
    }

    #[test]
    fn migrates_singular_github_installation_without_changing_the_revision_or_lease() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asm.db");
        let mut lease = generated_lease("generated");
        lease.generator_revision = Some(17);
        lease.credential_version = 4;
        let Some(GenerationRequest::GithubApp(scope)) = &mut lease.requested_generation else { unreachable!() };
        scope.permissions = None; // Legacy encoding, prior to the metadata-only default.
        let legacy = serde_json::json!({
            "type": "github_app",
            "client_id": "Iv1.fixture",
            "installation_id": 42,
            "ceiling": github_grant(),
        });
        {
            let store = Store::open(&path).unwrap();
            store.insert_lease(&lease).unwrap();
            store.db().execute(
                "INSERT INTO generators(id, name, config, revision, position) VALUES ('generator', 'release-bot', ?1, 17, 3)",
                [legacy.to_string()],
            ).unwrap();
        }

        for _ in 0..2 {
            let store = Store::open(&path).unwrap();
            let actual = store.get_generator("generator").unwrap().unwrap();
            let mut expected = generator("generator", "release-bot", 3);
            expected.revision = 17;
            assert_eq!(actual, expected);
            let persisted: String = store.db().query_row(
                "SELECT config FROM generators WHERE id = 'generator'", [], |row| row.get(0),
            ).unwrap();
            let persisted: serde_json::Value = serde_json::from_str(&persisted).unwrap();
            assert_eq!(persisted["installations"], serde_json::json!([github_grant()]));
            assert!(persisted.get("ceiling").is_none());
            assert!(persisted.get("installation_id").is_none());
            let actual = store.get_lease(&lease.id).unwrap().unwrap();
            assert!(actual.is_active(101));
            assert_eq!(actual.generation, lease.generation);
            assert_eq!(actual.generator_revision, lease.generator_revision);
            assert_eq!(actual.credential_version, lease.credential_version);
            assert_eq!(actual.requested_generation, lease.requested_generation);
        }
    }

    #[test]
    fn migration_never_repairs_a_disagreeing_installation_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asm.db");
        let legacy = serde_json::json!({
            "type": "github_app",
            "client_id": "Iv1.fixture",
            "installation_id": 43,
            "ceiling": github_grant(),
        }).to_string();
        {
            let store = Store::open(&path).unwrap();
            store.db().execute(
                "INSERT INTO generators(id, name, config, revision, position) VALUES ('bad', 'release-bot', ?1, 1, 1)", [&legacy],
            ).unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert!(store.get_generator("bad").is_err());
    }

    #[test]
    fn github_installations_round_trip_with_independent_ceilings() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("asm.db")).unwrap();
        let mut record = generator("multi", "multi-bot", 0);
        let GeneratorConfig::GithubApp(config) = &mut record.config else { unreachable!() };
        let mut second = github_grant();
        second.installation_id = 43;
        second.repositories[0].id = 9;
        second.repositories[0].full_name = "another/web".into();
        second.permissions.remove("contents");
        config.installations.push(second.clone());
        store.upsert_generator(&record).unwrap();
        assert_eq!(store.get_generator("multi").unwrap().unwrap().config.ceilings().count(), 2);
        assert_eq!(store.get_generator("multi").unwrap(), Some(record.clone()));
        let GeneratorConfig::GithubApp(config) = &mut record.config else { unreachable!() };
        config.installations.push(second);
        assert!(store.upsert_generator(&record).is_err());
    }

    #[test]
    fn generators_round_trip_update_and_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("asm.db")).unwrap();
        assert!(s.list_generators().unwrap().is_empty());
        assert!(s.get_generator("missing").unwrap().is_none());
        let first = generator("a", "release-bot", 1);
        let second = generator("b", "review-bot", 0);
        s.upsert_generator(&first).unwrap();
        s.upsert_generator(&second).unwrap();
        assert_eq!(s.list_generators().unwrap(), [second, first.clone()]);
        let mut edited = first;
        edited.name = "renamed".into();
        edited.revision = 2;
        let GeneratorConfig::GithubApp(config) = &mut edited.config else { unreachable!() };
        config.client_id = "Iv1.updated".into();
        s.upsert_generator(&edited).unwrap();
        assert_eq!(s.get_generator("a").unwrap(), Some(edited.clone()));
        s.replace_secret_hosts("a", "token", &["api.github.com".into()])
            .unwrap();
        s.delete_generator("a").unwrap();
        assert!(s.get_generator("a").unwrap().is_none());
        assert!(s.secret_hosts("a", "token").unwrap().is_empty());
        assert_eq!(s.list_generators().unwrap().len(), 1);
        edited.revision = 0;
        assert!(s.upsert_generator(&edited).is_err());
        edited.revision = u64::MAX;
        assert!(s.upsert_generator(&edited).is_err());
        assert!(s.get_generator("a").unwrap().is_none());
    }

    #[test]
    fn source_names_are_unique_across_tables_and_failed_edits_are_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("asm.db")).unwrap();
        let v = vault("vault", "static");
        let g = generator("generator", "release-bot", 0);
        s.upsert_vault(&v).unwrap();
        s.upsert_generator(&g).unwrap();
        let mut conflicting_vault = v.clone();
        conflicting_vault.name = g.name.clone();
        assert_eq!(
            s.upsert_vault(&conflicting_vault).unwrap_err().code,
            asm_proto::error::ErrorCode::Exists
        );
        let mut conflicting_generator = g.clone();
        conflicting_generator.name = v.name.clone();
        assert_eq!(
            s.upsert_generator(&conflicting_generator).unwrap_err().code,
            asm_proto::error::ErrorCode::Exists
        );
        assert_eq!(s.list_vaults().unwrap(), [v]);
        assert_eq!(s.list_generators().unwrap(), [g]);
        assert!(s.upsert_generator(&generator("other", "release-bot", 1)).is_err());
        assert!(s.upsert_vault(&vault("other", "static")).is_err());
    }

    #[test]
    fn concurrent_vault_and_generator_saves_cannot_share_a_source_name() {
        use std::sync::{Arc, Barrier};

        for separate_connection in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("asm.db");
            let first = Arc::new(Store::open(&path).unwrap());
            let second = if separate_connection {
                Arc::new(Store::open(&path).unwrap())
            } else {
                Arc::clone(&first)
            };
            let barrier = Arc::new(Barrier::new(2));
            let vault_store = Arc::clone(&first);
            let vault_barrier = Arc::clone(&barrier);
            let save_vault = std::thread::spawn(move || {
                vault_barrier.wait();
                vault_store.upsert_vault(&vault("vault", "same-name"))
            });
            let save_generator = std::thread::spawn(move || {
                barrier.wait();
                second.upsert_generator(&generator("generator", "same-name", 0))
            });
            let v = save_vault.join().unwrap();
            let g = save_generator.join().unwrap();
            assert_ne!(v.is_ok(), g.is_ok(), "exactly one save wins");
            let rejected = if let Err(e) = v { e } else { g.unwrap_err() };
            assert_eq!(rejected.code, asm_proto::error::ErrorCode::Exists);
            assert_eq!(
                first.list_vaults().unwrap().len() + first.list_generators().unwrap().len(),
                1
            );
        }
    }

    #[test]
    fn migrates_legacy_leases_without_generated_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asm.db");
        {
            let db = Connection::open(&path).unwrap();
            db.execute_batch(
                "CREATE TABLE leases(
                    id TEXT PRIMARY KEY, host_id TEXT NOT NULL, vault_id TEXT NOT NULL,
                    vault_name TEXT NOT NULL, secret_key TEXT NOT NULL, name TEXT NOT NULL,
                    mode TEXT NOT NULL, fields TEXT NOT NULL, hosts TEXT NOT NULL,
                    reason TEXT NOT NULL, agent TEXT NOT NULL, created_at INTEGER NOT NULL,
                    expires_at INTEGER, revoked_at INTEGER
                 );
                 INSERT INTO leases VALUES(
                    'old', 'host', 'vault', 'env', 'TOKEN', 'TOKEN', 'sentinel',
                    '[{\"field\":\"value\",\"sentinel\":\"asm_fixture\",\"path\":\"TOKEN\"}]',
                    '[\"api.example.com\"]', 'existing approval', 'agent', 10, 1000, NULL
                 );",
            )
            .unwrap();
        }
        for _ in 0..2 {
            let s = Store::open(&path).unwrap();
            let lease = s.get_lease("old").unwrap().unwrap();
            assert_eq!(lease.source_kind, SourceKind::Vault);
            assert_eq!(lease.generation, None);
            assert_eq!(lease.generator_revision, None);
            assert_eq!(lease.credential_expires_at, None);
            assert_eq!(lease.approval_order, None);
            assert_eq!(lease.credential_version, 0);
            assert_eq!(lease.requested_generation, None);
            assert_eq!(lease.mode, LeaseMode::Sentinel);
            assert_eq!(lease.fields[0].sentinel.as_deref(), Some("asm_fixture"));
            assert_eq!(lease.hosts, ["api.example.com"]);
            assert_eq!((lease.created_at, lease.expires_at), (10, Some(1000)));
            assert!(s.list_generators().unwrap().is_empty());
            assert_eq!(s.active_leases(20).unwrap().len(), 1);
        }
    }

    #[test]
    fn generated_lease_metadata_and_version_survive_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asm.db");
        let mut lease = generated_lease("generated");
        // The host's original repository name is provenance, not the approved
        // installation and repository IDs used on renewal.
        let Some(GenerationRequest::GithubApp(request)) = &mut lease.requested_generation else { unreachable!() };
        request.repositories = Some(vec!["acme/other".into()]);
        {
            let s = Store::open(&path).unwrap();
            lease.approval_order = Some(s.reserve_generator_approval_order().unwrap());
            s.insert_lease(&lease).unwrap();
            let loaded = s.get_lease(&lease.id).unwrap().unwrap();
            assert_eq!(loaded.source_kind, SourceKind::Generator);
            assert_eq!(loaded.generation, lease.generation);
            assert_eq!(loaded.requested_generation, lease.requested_generation);
            assert_eq!(loaded.generator_revision, Some(1));
            assert_eq!(loaded.approval_order, Some(1));
            assert_eq!(loaded.credential_version, 1);
            assert_eq!(loaded.credential_expires_at, Some(3_700));
            assert_eq!(s.update_generated_credential(&lease.id, 1, 6_700).unwrap(), 2);
            assert!(s.update_generated_credential(&lease.id, 1, 9_700).is_err());
        }
        let s = Store::open(&path).unwrap();
        let loaded = s.get_lease(&lease.id).unwrap().unwrap();
        assert_eq!(loaded.credential_version, 2);
        assert_eq!(loaded.credential_expires_at, Some(6_700));
        assert_eq!(loaded.created_at, lease.created_at);
        assert_eq!(loaded.expires_at, lease.expires_at);
        assert_eq!(loaded.fields, lease.fields);
        assert_eq!(loaded.generation, lease.generation);
        assert_eq!(loaded.approval_order, lease.approval_order);
        assert_eq!(s.update_generated_credential(&lease.id, 2, 10_000).unwrap(), 3);
        assert!(s.update_generated_credential(&lease.id, 3, 0).is_err());
        assert_eq!(s.get_lease(&lease.id).unwrap().unwrap().credential_version, 3);
        s.revoke_lease(&lease.id, 500).unwrap();
        assert!(s.update_generated_credential(&lease.id, 3, 11_000).is_err());
        assert_eq!(s.get_lease(&lease.id).unwrap().unwrap().credential_version, 3);
        assert!(s.update_generated_credential("missing", 1, 11_000).is_err());
    }

    #[test]
    fn generated_credential_version_and_sealed_token_change_together() {
        use crate::manager::resume::ResumeStore;
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asm.db");
        let s = Arc::new(Store::open(&path).unwrap());
        let resume = ResumeStore::open(s.clone(), Some([44; 32])).unwrap();
        let lease = generated_lease("generated");
        s.insert_lease(&lease).unwrap();
        resume.put("tokens", &lease.id, &"original").unwrap();
        let stale_writer = resume.seal("tokens", &lease.id, &"stale writer").unwrap();
        resume.close().unwrap();
        let s = Arc::new(Store::open(&path).unwrap());
        let reopened = ResumeStore::open(s.clone(), Some([44; 32])).unwrap();

        assert!(s.update_generated_credential_with_resume(&lease.id, 1, 6_700, &[stale_writer]).is_err());
        assert_eq!(s.get_lease(&lease.id).unwrap().unwrap().credential_version, 1);
        assert_eq!(reopened.get::<String>("tokens", &lease.id).unwrap().as_deref(), Some("original"));
        let next = reopened.seal("tokens", &lease.id, &"replacement").unwrap();
        assert_eq!(
            s.update_generated_credential_with_resume(&lease.id, 1, 6_700, &[next]).unwrap(),
            2,
        );
        let stale_version = reopened.seal("tokens", &lease.id, &"stale version").unwrap();
        assert!(s.update_generated_credential_with_resume(&lease.id, 1, 9_700, &[stale_version]).is_err());
        assert_eq!(s.get_lease(&lease.id).unwrap().unwrap().credential_version, 2);
        assert_eq!(reopened.get::<String>("tokens", &lease.id).unwrap().as_deref(), Some("replacement"));
    }

    #[test]
    fn credential_version_overflow_never_resets_or_changes_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("asm.db")).unwrap();
        let mut lease = generated_lease("generated");
        lease.credential_version = i64::MAX as u64;
        s.insert_lease(&lease).unwrap();
        assert!(s
            .update_generated_credential(&lease.id, i64::MAX as u64, 9_700)
            .is_err());
        let loaded = s.get_lease(&lease.id).unwrap().unwrap();
        assert_eq!(loaded.credential_version, i64::MAX as u64);
        assert_eq!(loaded.credential_expires_at, lease.credential_expires_at);
        lease.id = "too-large".into();
        lease.credential_version = u64::MAX;
        assert!(s.insert_lease(&lease).is_err());
        assert!(s.get_lease("too-large").unwrap().is_none());
    }

    #[test]
    fn concurrent_credential_updates_commit_only_one_next_version() {
        use std::sync::{Arc, Barrier};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asm.db");
        let first = Arc::new(Store::open(&path).unwrap());
        let second = Store::open(&path).unwrap();
        first.insert_lease(&generated_lease("generated")).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let first_store = Arc::clone(&first);
        let first_barrier = Arc::clone(&barrier);
        let a = std::thread::spawn(move || {
            first_barrier.wait();
            first_store.update_generated_credential("generated", 1, 6_700)
        });
        let b = std::thread::spawn(move || {
            barrier.wait();
            second.update_generated_credential("generated", 1, 7_700)
        });
        let a = a.join().unwrap();
        let b = b.join().unwrap();
        assert_ne!(a.is_ok(), b.is_ok());
        assert_eq!(a.or(b).unwrap(), 2);
        let loaded = first.get_lease("generated").unwrap().unwrap();
        assert_eq!(loaded.credential_version, 2);
        assert!([Some(6_700), Some(7_700)].contains(&loaded.credential_expires_at));
    }

    #[test]
    fn corrupt_generated_rows_fail_closed_in_every_lease_query() {
        let assignments = [
            "source_kind = 'unknown'",
            "source_kind = 'vault'",
            "mode = 'unknown'",
            "generation = NULL",
            "generation = '{}'",
            "generation = 'not json'",
            "generator_revision = NULL",
            "generator_revision = 0",
            "generator_revision = -1",
            "credential_expires_at = NULL",
            "credential_expires_at = 0",
            "approval_order = NULL",
            "approval_order = 0",
            "approval_order = -1",
            "credential_version = 0",
            "credential_version = -1",
            "requested_generation = 'not json'",
            "requested_generation = '{\"provider\":\"github_app\",\"scope\":{\"repositories\":[]}}'",
            "requested_generation = '{\"provider\":\"github_app\",\"scope\":{\"repositories\":[\"Acme/Web\"]}}'",
            "requested_generation = '{\"provider\":\"gcloud\",\"scope\":{}}'",
            "expires_at = created_at",
        ];
        for assignment in assignments {
            let dir = tempfile::tempdir().unwrap();
            let s = Store::open(&dir.path().join("asm.db")).unwrap();
            s.insert_lease(&generated_lease("generated")).unwrap();
            s.db()
                .execute_batch(&format!("UPDATE leases SET {assignment} WHERE id = 'generated';"))
                .unwrap();
            assert!(s.get_lease("generated").is_err(), "{assignment}");
            assert!(s.list_leases().is_err(), "{assignment}");
            assert!(s.active_leases(50).is_err(), "{assignment}");
            assert!(s.leases_of_host("host").is_err(), "{assignment}");
            assert!(s.update_generated_credential("generated", 1, 6_700).is_err(), "{assignment}");
        }
    }

    #[test]
    fn invalid_generated_grants_and_incomplete_inserts_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("asm.db")).unwrap();
        let mut lease = generated_lease("generated");
        lease.generation = None;
        assert!(s.insert_lease(&lease).is_err());
        assert!(s.list_leases().unwrap().is_empty());
        for malformed in [
            GithubGrant { installation_id: 0, ..github_grant() },
            GithubGrant { repositories: vec![], ..github_grant() },
            GithubGrant {
                repositories: vec![GithubRepository { id: 0, full_name: "acme/web".into() }],
                ..github_grant()
            },
            GithubGrant { permissions: Default::default(), ..github_grant() },
            GithubGrant {
                permissions: [("metadata".into(), GithubPermission::Write)].into(),
                ..github_grant()
            },
        ] {
            let mut lease = generated_lease("generated");
            lease.generation = Some(GenerationGrant::GithubApp(malformed));
            assert!(s.insert_lease(&lease).is_err());
            s.insert_lease(&generated_lease("generated")).unwrap();
            s.db().execute(
                "UPDATE leases SET generation = ?1 WHERE id = 'generated'",
                [serde_json::to_string(&lease.generation.unwrap()).unwrap()],
            ).unwrap();
            assert!(s.get_lease("generated").is_err());
            s.db().execute("DELETE FROM leases WHERE id = 'generated'", []).unwrap();
        }
    }

    #[test]
    fn approval_order_is_atomic_durable_and_checked() {
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asm.db");
        {
            let stores = [
                Arc::new(Store::open(&path).unwrap()),
                Arc::new(Store::open(&path).unwrap()),
            ];
            let workers: Vec<_> = (0..8)
                .map(|index| {
                    let store = Arc::clone(&stores[index % stores.len()]);
                    std::thread::spawn(move || {
                        (0..16)
                            .map(|_| store.reserve_generator_approval_order().unwrap())
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            let mut orders: Vec<_> = workers
                .into_iter()
                .flat_map(|worker| worker.join().unwrap())
                .collect();
            orders.sort_unstable();
            assert_eq!(orders, (1..=128).collect::<Vec<u64>>());
        }
        let s = Store::open(&path).unwrap();
        assert_eq!(s.reserve_generator_approval_order().unwrap(), 129);
        for invalid in ["-1", "broken", "9223372036854775808"] {
            s.set_setting("generator_approval_order", invalid).unwrap();
            assert!(s.reserve_generator_approval_order().is_err());
            assert_eq!(s.get_setting("generator_approval_order").unwrap().as_deref(), Some(invalid));
        }
        s.set_setting("generator_approval_order", &(i64::MAX - 1).to_string()).unwrap();
        assert_eq!(s.reserve_generator_approval_order().unwrap(), i64::MAX as u64);
        assert!(s.reserve_generator_approval_order().is_err());
        assert_eq!(
            s.get_setting("generator_approval_order").unwrap().unwrap(),
            i64::MAX.to_string()
        );
    }

    #[test]
    fn partial_lease_migration_never_reclassifies_an_incomplete_generator() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asm.db");
        {
            let db = Connection::open(&path).unwrap();
            db.execute_batch(
                "CREATE TABLE leases(
                    id TEXT PRIMARY KEY, host_id TEXT NOT NULL, vault_id TEXT NOT NULL,
                    vault_name TEXT NOT NULL, secret_key TEXT NOT NULL, name TEXT NOT NULL,
                    mode TEXT NOT NULL, fields TEXT NOT NULL, hosts TEXT NOT NULL,
                    reason TEXT NOT NULL, agent TEXT NOT NULL, created_at INTEGER NOT NULL,
                    expires_at INTEGER, revoked_at INTEGER,
                    source_kind TEXT NOT NULL DEFAULT 'vault', generation TEXT
                 );
                 INSERT INTO leases VALUES(
                    'incomplete', 'host', 'generator', 'release-bot', 'token', 'GH_TOKEN',
                    'raw', '[{\"field\":\"value\",\"sentinel\":null,\"path\":\"GH_TOKEN\"}]',
                    '[]', 'existing approval', 'agent', 100, 43300, NULL, 'generator', NULL
                 );",
            )
            .unwrap();
        }
        let s = Store::open(&path).unwrap();
        assert!(s.get_lease("incomplete").is_err());
        s.insert_lease(&generated_lease("complete")).unwrap();
        assert_eq!(
            s.get_lease("complete").unwrap().unwrap().source_kind,
            SourceKind::Generator
        );
        drop(s);
        let s = Store::open(&path).unwrap();
        assert!(s.get_lease("incomplete").is_err());
        assert_eq!(
            s.get_lease("complete").unwrap().unwrap().credential_version,
            1
        );
    }

    #[test]
    fn approval_order_survives_same_second_reversed_completion() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asm.db");
        {
            let s = Store::open(&path).unwrap();
            let mut first = generated_lease("first-decision");
            first.approval_order = Some(s.reserve_generator_approval_order().unwrap());
            let mut second = generated_lease("second-decision");
            second.vault_id = "other-generator".into();
            second.approval_order = Some(s.reserve_generator_approval_order().unwrap());
            assert_eq!(first.created_at, second.created_at);
            s.insert_lease(&second).unwrap();
            s.insert_lease(&first).unwrap();
        }
        let s = Store::open(&path).unwrap();
        let mut leases = s.leases_of_host("host").unwrap();
        leases.sort_unstable_by_key(|lease| lease.approval_order);
        assert_eq!(leases[0].id, "first-decision");
        assert_eq!(leases[1].id, "second-decision");
        assert_eq!(leases[1].approval_order, Some(2));
        assert_eq!(s.reserve_generator_approval_order().unwrap(), 3);
    }

    #[test]
    fn credential_update_cannot_turn_a_static_lease_into_generated_authority() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("asm.db")).unwrap();
        let mut lease = generated_lease("static");
        lease.source_kind = SourceKind::Vault;
        lease.generation = None;
        lease.generator_revision = None;
        lease.credential_expires_at = None;
        lease.approval_order = None;
        lease.credential_version = 0;
        lease.requested_generation = None;
        s.insert_lease(&lease).unwrap();
        assert!(s.update_generated_credential("static", 0, 6_700).is_err());
        let loaded = s.get_lease("static").unwrap().unwrap();
        assert_eq!(loaded.source_kind, SourceKind::Vault);
        assert_eq!(loaded.credential_version, 0);
        assert_eq!(loaded.credential_expires_at, None);
    }

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
            request_id: None,
        }
    }

    #[test]
    fn migrates_activity_without_request_id_column() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asm.db");
        {
            // The `activity` table as created by builds before the request link.
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
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
                 INSERT INTO activity VALUES
                   (1, '2026-11-16T00:00:00Z', 'requests', 'requested', NULL, 'X', 'get X requested', '{\"request_id\":\"r1\"}'),
                   (2, '2026-11-16T00:00:01Z', 'requests', 'denied', NULL, 'X', 'get X denied', '{\"request_id\":\"r1\"}'),
                   (3, '2026-11-16T00:00:02Z', 'pairing', 'approved', NULL, NULL, 'pairing of box approved', '{\"request_id\":\"p1\"}'),
                   (4, '2026-11-16T00:00:03Z', 'proxy', 'started', NULL, NULL, 'proxy started', NULL),
                   (5, '2026-11-16T00:00:04Z', 'vaults', 'added', NULL, NULL, 'bad detail', 'not json');",
            )
            .unwrap();
        }
        let s = Store::open(&path).unwrap();
        assert_eq!(
            s.activity_row_for_request("r1").unwrap(),
            Some(2),
            "outcome row, not the request"
        );
        assert_eq!(s.activity_row_for_request("p1").unwrap(), Some(3));
        assert_eq!(s.activity_row_for_request("nope").unwrap(), None);
        // New rows carry the column.
        s.insert_activity(&[NewActivity {
            kind: "approved",
            request_id: Some("r2".into()),
            ..activity("2026-11-16T00:00:05Z", "requests", None, "get Y approved")
        }])
        .unwrap();
        assert_eq!(s.activity_row_for_request("r2").unwrap(), Some(6));
        drop(s);
        // Opening again is a no-op.
        let s = Store::open(&path).unwrap();
        assert_eq!(s.activity_row_for_request("r1").unwrap(), Some(2));
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
            source_kind: SourceKind::Vault,
            generation: None,
            generator_revision: None,
            credential_expires_at: None,
            approval_order: None,
            credential_version: 0,
            requested_generation: None,
            login: None,
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
