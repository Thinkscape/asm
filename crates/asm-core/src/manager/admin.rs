//! Operations behind the settings window: vaults, hosts, pairing codes, leases, proxy and
//! general settings.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use asm_proto::crypto::new_uuid_v4;
use asm_proto::pairing::UnattendedCode;
use asm_proto::rules::validate_agent_text;
use asm_proto::wire::LeaseMode;

use super::{
    Core, TOPIC_HOSTS, TOPIC_LEASES, TOPIC_PROXY, TOPIC_SETTINGS, TOPIC_VAULTS, effective_config,
    lock, now, to_system_time,
};
use crate::error::{CoreError, Result};
use crate::ffi;
use crate::proxy::ProxyConfig;
use crate::store::{PairingCodeRecord, VaultRecord};
use crate::vault::registry::{Registry, VaultEntry};
use crate::vault::{BitwardenSecrets, VaultConfig, VaultStatus, bitwarden, creds};

const CLIENT_SECRET: &str = "client_secret";
const MASTER_PASSWORD: &str = "master_password";

fn vault_kind(c: &VaultConfig) -> ffi::VaultKind {
    match c {
        VaultConfig::Bitwarden(_) => ffi::VaultKind::Bitwarden,
        VaultConfig::EnvFile { .. } => ffi::VaultKind::EnvFile,
        VaultConfig::Keychain => ffi::VaultKind::Keychain,
    }
}

fn parse_time(s: &Option<String>) -> Option<std::time::SystemTime> {
    s.as_deref().and_then(asm_proto::time::parse_rfc3339)
}

/// Trimmed, non-empty host name or address for a hint.
fn check_hint(h: &str) -> Result<String> {
    let h = h.trim().to_string();
    if h.is_empty()
        || h.len() > 253
        || h.chars()
            .any(|c| c.is_whitespace() || c == '/' || c.is_control())
    {
        return Err(CoreError::invalid(format!("invalid hostname hint {h:?}")));
    }
    Ok(h)
}

impl Core {
    // ---- vaults ----

    fn vault_info(&self, rec: &VaultRecord) -> ffi::VaultInfo {
        let (status, secret_count, note) = match self.registry.get(&rec.id) {
            Some(v) => {
                let status = v.provider.status();
                let count = if status == VaultStatus::Ready {
                    v.provider.list().ok().map(|l| l.len() as u32)
                } else {
                    None
                };
                (status.into(), count, v.provider.note())
            }
            None => {
                let msg = lock(&self.vault_errors)
                    .get(&rec.id)
                    .cloned()
                    .unwrap_or_else(|| "vault could not be started".to_string());
                (ffi::VaultStatus::Error { message: msg }, None, None)
            }
        };
        ffi::VaultInfo {
            id: rec.id.clone(),
            name: rec.name.clone(),
            kind: vault_kind(&rec.config),
            status,
            secret_count,
            note,
            config: rec.config.clone().into(),
        }
    }

    pub fn list_vaults(&self) -> Vec<ffi::VaultInfo> {
        match self.store.list_vaults() {
            Ok(v) => v.iter().map(|r| self.vault_info(r)).collect(),
            Err(e) => {
                log::error!("list vaults: {}", e.message);
                Vec::new()
            }
        }
    }

    /// Build (or rebuild) the provider of a stored vault and register it.
    fn start_vault(&self, rec: &VaultRecord) {
        let cfg = effective_config(&self.settings(), &rec.config);
        match Registry::build_provider(&self.dirs, &rec.id, &cfg) {
            Ok(provider) => {
                lock(&self.vault_errors).remove(&rec.id);
                self.registry.insert(VaultEntry {
                    id: rec.id.clone(),
                    name: rec.name.clone(),
                    config: rec.config.clone(),
                    provider,
                });
            }
            Err(e) => {
                if let Some(old) = self.registry.remove(&rec.id) {
                    drop(old);
                }
                lock(&self.vault_errors).insert(rec.id.clone(), e.message);
            }
        }
    }

    pub fn save_vault(&self, draft: ffi::VaultDraft) -> Result<ffi::VaultInfo> {
        let name = draft.name.trim().to_string();
        let n = name.chars().count();
        if n == 0 || n > 64 || name.contains('/') || name.chars().any(char::is_control) {
            return Err(CoreError::invalid(
                "vault names are 1–64 characters without '/'",
            ));
        }
        let config: VaultConfig = draft.config.into();
        let existing = self.store.list_vaults()?;
        let current = match &draft.id {
            Some(id) => Some(
                existing
                    .iter()
                    .find(|v| &v.id == id)
                    .cloned()
                    .ok_or_else(|| CoreError::not_found("no such vault"))?,
            ),
            None => None,
        };
        let id = current
            .as_ref()
            .map(|c| c.id.clone())
            .unwrap_or_else(new_uuid_v4);
        if existing.iter().any(|v| v.id != id && v.name == name) {
            return Err(CoreError::exists(format!(
                "a vault named {name:?} already exists"
            )));
        }
        if let Some(c) = &current
            && vault_kind(&c.config) != vault_kind(&config)
        {
            return Err(CoreError::invalid("a vault's type cannot be changed"));
        }
        match &config {
            VaultConfig::EnvFile { path } => {
                if !Path::new(path).is_absolute() {
                    return Err(CoreError::invalid(
                        "choose an absolute path for the .env file",
                    ));
                }
            }
            VaultConfig::Keychain => {
                if existing
                    .iter()
                    .any(|v| v.id != id && v.config == VaultConfig::Keychain)
                {
                    return Err(CoreError::exists(
                        "the macOS Keychain vault is already configured",
                    ));
                }
            }
            VaultConfig::Bitwarden(b) => {
                if b.server_url.trim().is_empty()
                    || b.email.trim().is_empty()
                    || b.client_id.trim().is_empty()
                {
                    return Err(CoreError::invalid(
                        "server URL, email and client id are required",
                    ));
                }
                let missing = draft.client_secret.is_empty() || draft.master_password.is_empty();
                if current.is_none() && missing {
                    return Err(CoreError::invalid(
                        "client secret and master password are required",
                    ));
                }
            }
        }
        let position = current
            .as_ref()
            .map(|c| c.position)
            .unwrap_or_else(|| existing.iter().map(|v| v.position).max().unwrap_or(0) + 1);
        let rec = VaultRecord {
            id: id.clone(),
            name,
            config,
            position,
        };
        self.store.upsert_vault(&rec)?;
        if matches!(rec.config, VaultConfig::Bitwarden(_)) {
            let set = || -> Result<()> {
                if !draft.client_secret.is_empty() {
                    creds::set(&id, CLIENT_SECRET, &draft.client_secret)?;
                }
                if !draft.master_password.is_empty() {
                    creds::set(&id, MASTER_PASSWORD, &draft.master_password)?;
                }
                Ok(())
            };
            if let Err(e) = set() {
                if current.is_none() {
                    let _ = self.store.delete_vault(&id);
                    let _ = creds::delete_all(&id);
                }
                return Err(e);
            }
        }
        self.start_vault(&rec);
        self.notify(TOPIC_VAULTS);
        self.sync_proxy(true);
        Ok(self.vault_info(&rec))
    }

    pub fn remove_vault(&self, id: &str) -> Result<()> {
        let rec = self
            .store
            .list_vaults()?
            .into_iter()
            .find(|v| v.id == id)
            .ok_or_else(|| CoreError::not_found("no such vault"))?;
        self.registry.remove(id);
        lock(&self.vault_errors).remove(id);
        self.store.delete_vault(id)?;
        if matches!(rec.config, VaultConfig::Bitwarden(_)) {
            if let Err(e) = creds::delete_all(id) {
                log::warn!("vault credentials: {}", e.message);
            }
            let _ = std::fs::remove_dir_all(self.dirs.bw_vault(id));
        }
        let t = now();
        let mut revoked = false;
        for l in self
            .store
            .active_leases(t)?
            .into_iter()
            .filter(|l| l.vault_id == id)
        {
            revoked |= self.store.revoke_lease(&l.id, t)?;
        }
        self.sync_proxy(false);
        self.notify(TOPIC_VAULTS);
        if revoked {
            self.notify(TOPIC_LEASES);
        }
        Ok(())
    }

    pub fn bitwarden_connect(&self, draft: ffi::VaultDraft) -> Result<Vec<ffi::CollectionInfo>> {
        let VaultConfig::Bitwarden(cfg) = VaultConfig::from(draft.config) else {
            return Err(CoreError::invalid("not a Bitwarden vault"));
        };
        let stored = |kind: &str| -> Result<Option<String>> {
            match &draft.id {
                Some(id) => creds::get(id, kind),
                None => Ok(None),
            }
        };
        let client_secret = if draft.client_secret.is_empty() {
            stored(CLIENT_SECRET)?
        } else {
            Some(draft.client_secret)
        };
        let master_password = if draft.master_password.is_empty() {
            stored(MASTER_PASSWORD)?
        } else {
            Some(draft.master_password)
        };
        let (Some(client_secret), Some(master_password)) = (client_secret, master_password) else {
            return Err(CoreError::invalid(
                "enter the client secret and master password",
            ));
        };
        let vault_id = draft.id.unwrap_or_else(new_uuid_v4);
        let VaultConfig::Bitwarden(cfg) =
            effective_config(&self.settings(), &VaultConfig::Bitwarden(cfg))
        else {
            unreachable!("effective_config keeps the vault type")
        };
        let cols = bitwarden::connect(
            &self.dirs,
            &vault_id,
            &cfg,
            &BitwardenSecrets {
                client_secret,
                master_password,
            },
        )?;
        Ok(cols.into_iter().map(Into::into).collect())
    }

    pub fn sync_vault(&self, id: &str) -> Result<()> {
        match self.registry.get(id) {
            Some(v) => {
                let r = v.provider.sync();
                self.notify(TOPIC_VAULTS);
                r?;
            }
            None => {
                // A vault that failed to start: try again.
                let rec = self
                    .store
                    .list_vaults()?
                    .into_iter()
                    .find(|v| v.id == id)
                    .ok_or_else(|| CoreError::not_found("no such vault"))?;
                self.start_vault(&rec);
                self.notify(TOPIC_VAULTS);
            }
        }
        self.sync_proxy(true);
        Ok(())
    }

    // ---- hosts ----

    pub fn list_hosts(&self) -> Vec<ffi::HostRecord> {
        let t = now();
        let mut active: HashMap<String, u32> = HashMap::new();
        for l in self.store.active_leases(t).unwrap_or_default() {
            *active.entry(l.host_id).or_default() += 1;
        }
        self.store
            .list_hosts()
            .unwrap_or_default()
            .into_iter()
            .map(|h| ffi::HostRecord {
                agents: self
                    .store
                    .agents_of(&h.id)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(agent, seen)| ffi::AgentSeen {
                        agent,
                        last_seen: to_system_time(seen),
                    })
                    .collect(),
                active_leases: active.get(&h.id).copied().unwrap_or(0),
                host_id: h.id,
                info: h.info.into(),
                observed_address: h.address,
                paired_at: to_system_time(h.paired_at),
                last_seen: h.last_seen.map(to_system_time),
            })
            .collect()
    }

    /// Invalidate the host's token, cancel its pending requests and revoke its leases.
    pub fn revoke_host(&self, host_id: &str) -> Result<()> {
        let t = now();
        if !self.store.revoke_host(host_id, t)? {
            return Err(CoreError::not_found("no such host"));
        }
        self.cancel_host_requests(host_id);
        for l in self
            .store
            .leases_of_host(host_id)?
            .into_iter()
            .filter(|l| l.is_active(t))
        {
            self.store.revoke_lease(&l.id, t)?;
        }
        self.sync_proxy(false);
        self.notify(TOPIC_HOSTS);
        self.notify(TOPIC_LEASES);
        Ok(())
    }

    // ---- pairing codes ----

    fn code_info(c: PairingCodeRecord, t: i64) -> ffi::PairingCodeInfo {
        let status = if c.expires_at.is_some_and(|e| e <= t) {
            ffi::PairingCodeStatus::Expired
        } else if c.max_uses.is_some_and(|m| c.uses >= m) {
            ffi::PairingCodeStatus::UsedUp
        } else {
            ffi::PairingCodeStatus::Active
        };
        ffi::PairingCodeInfo {
            id: c.id,
            label: c.label,
            created_at: to_system_time(c.created_at),
            expires_at: c.expires_at.map(to_system_time),
            uses: c.uses,
            max_uses: c.max_uses,
            status,
        }
    }

    pub fn create_pairing_code(
        &self,
        label: &str,
        expiry_secs: Option<u64>,
        max_uses: Option<u32>,
    ) -> Result<ffi::CreatedPairingCode> {
        let label = label.trim().to_string();
        if label.is_empty() || label.chars().count() > 100 || label.chars().any(char::is_control) {
            return Err(CoreError::invalid("label must be 1–100 characters"));
        }
        if max_uses == Some(0) {
            return Err(CoreError::invalid("max uses must be at least 1"));
        }
        let t = now();
        let code = UnattendedCode::generate(&self.cert.sha256);
        let rec = PairingCodeRecord {
            id: new_uuid_v4(),
            label,
            created_at: t,
            expires_at: expiry_secs.map(|s| t.saturating_add(s.min(i64::MAX as u64) as i64)),
            max_uses,
            uses: 0,
            revoked_at: None,
        };
        self.store
            .insert_pairing_code(&rec, &code.secret_sha256())?;
        let s = self.settings();
        let host = s
            .proxy_hints
            .first()
            .cloned()
            .or_else(|| super::netinfo::local_names().into_iter().next())
            .unwrap_or_else(|| "this-mac".into());
        let port = self.api_addr().map(|a| a.port()).unwrap_or(s.api_port);
        let code = code.to_string();
        self.notify(TOPIC_HOSTS);
        Ok(ffi::CreatedPairingCode {
            info: Self::code_info(rec, t),
            command: format!("asm pair {host}:{port} {code}"),
            code,
        })
    }

    pub fn list_pairing_codes(&self) -> Vec<ffi::PairingCodeInfo> {
        let t = now();
        self.store
            .list_pairing_codes()
            .unwrap_or_default()
            .into_iter()
            .map(|c| Self::code_info(c, t))
            .collect()
    }

    pub fn revoke_pairing_code(&self, id: &str) -> Result<()> {
        if !self.store.revoke_pairing_code(id, now())? {
            return Err(CoreError::not_found("no such pairing code"));
        }
        self.notify(TOPIC_HOSTS);
        Ok(())
    }

    // ---- leases ----

    pub fn list_leases(&self) -> Vec<ffi::LeaseInfo> {
        let t = now();
        let suspended = self.suspended();
        let mut labels: HashMap<String, String> = HashMap::new();
        self.store
            .list_leases()
            .unwrap_or_default()
            .into_iter()
            .map(|l| {
                let host_label = labels
                    .entry(l.host_id.clone())
                    .or_insert_with(|| {
                        self.store
                            .get_host(&l.host_id)
                            .ok()
                            .flatten()
                            .map(|h| h.info.hostname)
                            .unwrap_or_default()
                    })
                    .clone();
                let status = l.status(t);
                ffi::LeaseInfo {
                    suspended: status == asm_proto::wire::LeaseStatus::Active
                        && suspended.contains_key(&l.id),
                    raw_delivered: l.mode == LeaseMode::Raw,
                    status: status.into(),
                    lease_id: l.id,
                    host_id: l.host_id,
                    host_label,
                    vault_id: l.vault_id,
                    vault_name: l.vault_name,
                    name: l.name,
                    mode: l.mode.into(),
                    hosts: l.hosts,
                    fields: l.fields.into_iter().map(|f| f.field).collect(),
                    reason: l.reason,
                    agent: l.agent,
                    created_at: to_system_time(l.created_at),
                    expires_at: l.expires_at.map(to_system_time),
                }
            })
            .collect()
    }

    pub fn revoke_lease(&self, id: &str) -> Result<()> {
        let lease = self
            .store
            .get_lease(id)?
            .ok_or_else(|| CoreError::not_found("no such lease"))?;
        if self.store.revoke_lease(&lease.id, now())? {
            self.sync_proxy(false);
            self.notify(TOPIC_LEASES);
        }
        Ok(())
    }

    // ---- proxy ----

    pub fn proxy_settings(&self) -> ffi::ProxySettings {
        let s = self.settings();
        let p = self.proxy.config();
        ffi::ProxySettings {
            bind_address: p.bind,
            port: p.port,
            hints: s.proxy_hints,
            http_port: p.http_port,
            https_port: p.https_port,
            management_port: p.mgmt_port,
            metrics_port: p.metrics_port,
            max_request_body_bytes: p.max_body,
            allow_plain_http: p.allow_plain_http,
        }
    }

    pub fn set_proxy_settings(&self, ps: ffi::ProxySettings) -> Result<()> {
        let bind = ps.bind_address.trim().to_string();
        bind.parse::<IpAddr>()
            .map_err(|_| CoreError::invalid(format!("invalid bind address {bind:?}")))?;
        let ports = [
            ps.port,
            ps.http_port,
            ps.https_port,
            ps.management_port,
            ps.metrics_port,
        ];
        if ports.contains(&0) {
            return Err(CoreError::invalid("ports must be between 1 and 65535"));
        }
        for (i, a) in ports.iter().enumerate() {
            if ports[i + 1..].contains(a) {
                return Err(CoreError::invalid(format!("port {a} is used twice")));
            }
        }
        if ps.max_request_body_bytes == 0 {
            return Err(CoreError::invalid(
                "the maximum request body size must be positive",
            ));
        }
        let mut hints: Vec<String> = Vec::new();
        for h in &ps.hints {
            let h = check_hint(h)?;
            validate_agent_text("hint", &h)?;
            if !hints.contains(&h) {
                hints.push(h);
            }
        }
        let mut s = self.settings();
        let cfg = ProxyConfig {
            bind,
            port: ps.port,
            http_port: ps.http_port,
            https_port: ps.https_port,
            mgmt_port: ps.management_port,
            metrics_port: ps.metrics_port,
            max_body: ps.max_request_body_bytes,
            allow_plain_http: ps.allow_plain_http,
            upstream_deny_cidrs: s.proxy.upstream_deny_cidrs.clone(),
        };
        if cfg != self.proxy.config() {
            self.proxy.set_config(cfg.clone())?;
        }
        s.proxy = cfg;
        s.proxy_hints = hints;
        self.set_settings(s)?;
        self.notify(TOPIC_PROXY);
        self.notify(TOPIC_SETTINGS);
        Ok(())
    }

    pub fn proxy_status(&self) -> ffi::ProxyStatus {
        let st = self.proxy.status();
        let (entries, suspended) = {
            let ps = lock(&self.proxy_state);
            (
                ps.entries.values().map(|e| e.len() as u32).sum(),
                ps.suspended.len() as u32,
            )
        };
        ffi::ProxyStatus {
            running: st.running,
            pid: st.pid,
            healthy: st.healthy,
            last_reload: parse_time(&st.last_reload),
            ca_path: st.ca_path,
            ca_expiry: parse_time(&st.ca_expiry),
            ca_pem: self.proxy.ca_pem().ok(),
            error: st.error,
            active_entries: entries,
            suspended_leases: suspended,
        }
    }

    pub fn restart_proxy(&self) -> Result<()> {
        let r = self.proxy.restart();
        self.notify(TOPIC_PROXY);
        r
    }

    // ---- general settings ----

    pub fn general_settings(&self) -> ffi::GeneralSettings {
        let s = self.settings();
        ffi::GeneralSettings {
            api_bind_address: s.api_bind,
            api_port: s.api_port,
            default_lease_secs: s.lease_default_secs,
            pending_lifetime_secs: s.request_lifetime_secs,
            bw_path: s.bw_path.or_else(bitwarden::default_bw_path),
            version: asm_proto::VERSION.to_string(),
            cert_sha256: self.cert.sha256_hex(),
            listening_on: self.api_addr().map(|a| a.to_string()).unwrap_or_default(),
        }
    }

    pub fn set_general_settings(self: &Arc<Self>, g: ffi::GeneralSettings) -> Result<()> {
        if g.pending_lifetime_secs < 10 {
            return Err(CoreError::invalid(
                "pending requests must live at least 10 seconds",
            ));
        }
        if g.default_lease_secs == Some(0) {
            return Err(CoreError::invalid(
                "the default lease duration must be positive",
            ));
        }
        let bind = g.api_bind_address.trim().to_string();
        bind.parse::<IpAddr>()
            .map_err(|_| CoreError::invalid(format!("invalid bind address {bind:?}")))?;
        let bw_path = g
            .bw_path
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty());
        if let Some(p) = &bw_path
            && !Path::new(p).is_absolute()
        {
            return Err(CoreError::invalid("the bw path must be absolute"));
        }
        let mut s = self.settings();
        if bind != s.api_bind || g.api_port != s.api_port {
            self.bind_api(&bind, g.api_port)?;
        }
        s.api_bind = bind;
        s.api_port = g.api_port;
        s.lease_default_secs = g.default_lease_secs;
        s.request_lifetime_secs = g.pending_lifetime_secs;
        // Store only an explicit choice; the default path is shown but not pinned.
        s.bw_path = bw_path.filter(|p| Some(p.as_str()) != bitwarden::default_bw_path().as_deref());
        self.set_settings(s)?;
        self.notify(TOPIC_SETTINGS);
        Ok(())
    }
}
