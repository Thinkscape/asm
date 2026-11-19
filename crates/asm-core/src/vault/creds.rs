//! Manager credentials in the login keychain: generic passwords with service
//! `net.thinkscape.asm` and account `<source_id>:<kind>`. Bitwarden client secrets
//! and generator credentials (GitHub App keys or Google Cloud ADC) are manager-only.
//! The per-database restart encryption key is also manager-only.
//! The Bitwarden master password is never stored; earlier builds' copies are removed
//! at startup and source deletion.
//! The keychain vault provider never exposes this service.

use core_foundation::base::TCFType;
use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};
use security_framework::passwords;
use security_framework_sys::base::{SecKeychainRef, errSecItemNotFound, errSecSuccess};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

pub const SERVICE: &str = "net.thinkscape.asm";
pub const CLIENT_SECRET: &str = "client_secret";
pub const GITHUB_PRIVATE_KEY: &str = "github_private_key";
pub const GCLOUD_ADC: &str = "gcloud_adc";
/// Written by earlier builds only; never written now.
const LEGACY_MASTER_PASSWORD: &str = "master_password";
const RESUME_KEY: &str = "resume_key_v1";

unsafe extern "C" {
    fn SecKeychainGetStatus(keychain: SecKeychainRef, status: *mut u32) -> i32;
}

fn resume_keychain() -> Result<SecKeychain> {
    const UNLOCKED: u32 = 1; // kSecUnlockStateStatus, SecKeychain.h
    let keychain = SecKeychain::default_for_domain(SecPreferencesDomain::User)
        .map_err(|e| err("open for restart key", e))?;
    let mut status = 0;
    // The referenced keychain and writable status slot both outlive the call.
    let result = unsafe { SecKeychainGetStatus(keychain.as_concrete_TypeRef(), &mut status) };
    if result != errSecSuccess {
        return Err(err(
            "check restart keychain",
            security_framework::base::Error::from_code(result),
        ));
    }
    if status & UNLOCKED == 0 {
        return Err(CoreError::internal("unlock the login keychain to access restart state"));
    }
    Ok(keychain)
}

pub(crate) fn create_resume_key(database_id: &[u8; 16], key: &[u8; 32]) -> Result<()> {
    // Create only: a duplicate item must never erase the original key.
    resume_keychain()?
        .add_generic_password(SERVICE, &account(&hex::encode(database_id), RESUME_KEY), key)
        .map_err(|e| err("create restart key", e))
}

pub(crate) fn load_resume_key(database_id: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    let (secret, _) = resume_keychain()?
        .find_generic_password(SERVICE, &account(&hex::encode(database_id), RESUME_KEY))
        .map_err(|e| {
            if e.code() == errSecItemNotFound {
                CoreError::internal("restart key is missing from the login keychain")
            } else {
                err("read restart key", e)
            }
        })?;
    let mut key = Zeroizing::new([0; 32]);
    if secret.len() != key.len() {
        return Err(CoreError::internal("restart key has an invalid length"));
    }
    key.copy_from_slice(&secret);
    Ok(key)
}

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
