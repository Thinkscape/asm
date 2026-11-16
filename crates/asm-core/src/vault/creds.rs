//! Vault credentials in the login keychain: generic passwords with service
//! `net.thinkscape.asm` and account `<vault_id>:<kind>` (kinds used: `client_secret`,
//! `master_password`). The keychain vault provider never exposes this service.

use security_framework::passwords;
use security_framework_sys::base::errSecItemNotFound;

use crate::error::{CoreError, Result};

pub const SERVICE: &str = "net.thinkscape.asm";
pub const KINDS: [&str; 2] = ["client_secret", "master_password"];

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

pub fn delete_all(vault_id: &str) -> Result<()> {
    for kind in KINDS {
        match passwords::delete_generic_password(SERVICE, &account(vault_id, kind)) {
            Ok(()) => {}
            Err(e) if e.code() == errSecItemNotFound => {}
            Err(e) => return Err(err("delete", e)),
        }
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
        assert_eq!(get(&id, "client_secret").unwrap(), None);
        set(&id, "client_secret", "s3cret-one").unwrap();
        set(&id, "client_secret", "s3cret-two").unwrap();
        set(&id, "master_password", "mp").unwrap();
        assert_eq!(
            get(&id, "client_secret").unwrap().as_deref(),
            Some("s3cret-two")
        );
        delete_all(&id).unwrap();
        delete_all(&id).unwrap();
        assert_eq!(get(&id, "master_password").unwrap(), None);
    }
}
