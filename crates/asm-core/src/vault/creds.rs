//! Manager credentials in the login keychain: generic passwords with service
//! `net.thinkscape.asm` and account `<source_id>:<kind>`. Bitwarden client secrets
//! and generator credentials (GitHub App keys or Google Cloud ADC) are manager-only.
//! The Bitwarden master password is never stored; earlier builds' copies are removed
//! at startup and source deletion.
//! The keychain vault provider never exposes this service.

use security_framework::passwords;
use security_framework_sys::base::errSecItemNotFound;

use crate::error::{CoreError, Result};

pub const SERVICE: &str = "net.thinkscape.asm";
pub const CLIENT_SECRET: &str = "client_secret";
pub const GITHUB_PRIVATE_KEY: &str = "github_private_key";
pub const GCLOUD_ADC: &str = "gcloud_adc";
/// Written by earlier builds only; never written now.
const LEGACY_MASTER_PASSWORD: &str = "master_password";

fn account(vault_id: &str, kind: &str) -> String {
    format!("{vault_id}:{kind}")
}

fn err(op: &str, e: security_framework::base::Error) -> CoreError {
    CoreError::internal(format!("keychain {op} failed: {e} ({})", e.code()))
}

pub fn set(vault_id: &str, kind: &str, value: &str) -> Result<()> {
    passwords::set_generic_password(SERVICE, &account(vault_id, kind), value.as_bytes())
        .map_err(|e| err("write", e))
}

pub fn get(vault_id: &str, kind: &str) -> Result<Option<String>> {
    match passwords::generic_password(passwords::PasswordOptions::new_generic_password(
        SERVICE,
        &account(vault_id, kind),
    )) {
        Ok(bytes) => String::from_utf8(bytes).map(Some).map_err(|_| {
            CoreError::internal(format!("stored {kind} for vault {vault_id} is not UTF-8"))
        }),
        Err(e) if e.code() == errSecItemNotFound => Ok(None),
        Err(e) => Err(err("read", e)),
    }
}

pub fn delete(vault_id: &str, kind: &str) -> Result<()> {
    match passwords::delete_generic_password(SERVICE, &account(vault_id, kind)) {
        Ok(()) => Ok(()),
        Err(e) if e.code() == errSecItemNotFound => Ok(()),
        Err(e) => Err(err("delete", e)),
    }
}

/// Start-up migration: remove a master password stored by an earlier build.
pub fn delete_legacy_master_password(vault_id: &str) -> Result<()> {
    delete(vault_id, LEGACY_MASTER_PASSWORD)
}

pub fn delete_all(vault_id: &str) -> Result<()> {
    for kind in [CLIENT_SECRET, GITHUB_PRIVATE_KEY, LEGACY_MASTER_PASSWORD] {
        delete(vault_id, kind)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Touches the real login keychain (may prompt); run with `--ignored`.
    #[test]
    #[ignore]
    fn round_trip_in_login_keychain() {
        let id = format!("test-{}", asm_proto::crypto::new_uuid_v4());
        assert_eq!(get(&id, CLIENT_SECRET).unwrap(), None);
        set(&id, CLIENT_SECRET, "s3cret-one").unwrap();
        set(&id, CLIENT_SECRET, "s3cret-two").unwrap();
        set(&id, LEGACY_MASTER_PASSWORD, "mp").unwrap();
        assert_eq!(
            get(&id, CLIENT_SECRET).unwrap().as_deref(),
            Some("s3cret-two")
        );
        delete_legacy_master_password(&id).unwrap();
        assert_eq!(get(&id, LEGACY_MASTER_PASSWORD).unwrap(), None);
        delete_all(&id).unwrap();
        delete_all(&id).unwrap();
        assert_eq!(get(&id, CLIENT_SECRET).unwrap(), None);
    }
}
