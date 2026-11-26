//! Continue the exact login the operator approved; never resolve a name, search by URL,
//! use a different lease or start a new approval.
use super::{Core, activity, lock};
use crate::error::{CoreError, Result};
use asm_proto::generators::SourceKind;
use asm_proto::time::fmt_unix;
use asm_proto::wire::{GetResult, LeaseMode, ResultFile};
use std::sync::Arc;

impl Core {
    pub(super) fn login_totp(&self, host: &str, proof: &[u8; 32], id: &str) -> Result<GetResult> {
        let unavailable = || CoreError::not_found("no active login grant with a one-time code for this machine");
        let lease = self.store.get_lease(id)?.filter(|lease| lease.host_id == host
            && lease.source_kind == SourceKind::Vault && lease.mode == LeaseMode::Sentinel
            && lease.login.is_some() && lease.expires_at.is_some() && lease.is_active(self.generation_now()))
            .ok_or_else(unavailable)?;
        let field = lease.fields.iter().find(|f| f.field == "totp" && f.sentinel.is_none()).ok_or_else(unavailable)?;
        let vault = self.registry.get(&lease.vault_id).ok_or_else(unavailable)?;
        // Vault I/O can block. Recheck authorization at delivery, not just before reading.
        let mut code = vault.provider.read_totp(&lease.secret_key)
            .map_err(|_| CoreError::vault_unavailable("the selected login's one-time code is unavailable"))?;
        let _authority = lock(&self.authorization);
        if self.store.host_by_proof(host, proof)?.is_none() {
            return Err(CoreError::unauthorized("token rejected; run asm pair"));
        }
        if !self.store.get_lease(id)?.is_some_and(|current| current == lease && current.is_active(self.generation_now()))
            || !self.registry.get(&lease.vault_id).is_some_and(|v| Arc::ptr_eq(&v.provider, &vault.provider)) {
            return Err(unavailable());
        }
        self.log(activity::Event::new(activity::Category::Requests, "reused", "One-time code from approved browser login")
            .host(Some(host)).secret(&lease.name).detail(serde_json::json!({"lease_id": id})));
        Ok(GetResult {
            lease_id: lease.id, mode: lease.mode, hosts: lease.hosts, expires_at: lease.expires_at.map(fmt_unix),
            files: vec![ResultFile { field: "totp".into(), relative_path: field.path.clone(),
                content: std::mem::take(&mut *code), substituted: Some(false) }],
            generation: None, operator_selected_grant: false, broader_lease_reuse: false, credential_expires_at: None,
            credential_version: None, generator_name: None, login: lease.login,
        })
    }
}
