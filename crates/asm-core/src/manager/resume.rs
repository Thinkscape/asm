//! Restart state containing secrets is encrypted before it reaches SQLite.
//! Only the fixed-size, per-database master key is kept in the login keychain.

use std::sync::Arc;

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};
use crate::store::Store;
use crate::vault::creds;

const NONCE_LEN: usize = 12;
const CHECK_DOMAIN: &[u8] = b"asm resume v1 key check";
const ENTRY_DOMAIN: &[u8] = b"asm resume v1 entry";

pub(crate) struct ResumeStore {
    store: Arc<Store>,
    database_id: [u8; 16],
    writer_id: [u8; 16],
    key: LessSafeKey,
}

/// Prepared mutation for use in the same transaction as its authority change.
/// Holds only ciphertext, never the value. Owns the route so a prepared write
/// can outlive the short state lock under which it was created.
pub(crate) struct SealedResume {
    pub(crate) writer_id: [u8; 16],
    route: String,
    namespace_len: usize,
    pub(crate) ciphertext: Option<Vec<u8>>,
}

impl SealedResume {
    fn new(writer_id: [u8; 16], namespace: &str, id: &str, ciphertext: Option<Vec<u8>>) -> Self {
        let mut route = String::with_capacity(namespace.len() + id.len());
        route.push_str(namespace);
        route.push_str(id);
        Self {
            writer_id,
            route,
            namespace_len: namespace.len(),
            ciphertext,
        }
    }

    pub(crate) fn route(&self) -> (&str, &str) {
        self.route.split_at(self.namespace_len)
    }
}

impl ResumeStore {
    pub(crate) fn open(store: Arc<Store>, test_key: Option<[u8; 32]>) -> Result<Self> {
        let test_key = test_key.map(Zeroizing::new);
        #[cfg(test)]
        if test_key.is_none() {
            return Err(CoreError::internal("resume test requires an injected key"));
        }
        Self::open_with_key(store, |id, creating| match &test_key {
            Some(key) => make_key(key),
            None if creating => {
                let mut raw = Zeroizing::new([0; 32]);
                fill_random(&mut raw[..])?;
                creds::create_resume_key(id, &raw)?;
                make_key(&raw)
            }
            None => make_key(&*creds::load_resume_key(id)?),
        })
    }

    fn open_with_key(
        store: Arc<Store>,
        key_for: impl Fn(&[u8; 16], bool) -> Result<LessSafeKey>,
    ) -> Result<Self> {
        let mut fresh_id = [0; 16];
        fill_random(&mut fresh_id)?;
        let mut writer_id = [0; 16];
        fill_random(&mut writer_id)?;
        let (database_id, key) = store.claim_resume_writer(
            fresh_id,
            &writer_id,
            |id, mut verifier| {
                let key = key_for(id, false)?;
                let aad = Aad::from(check_aad(id));
                if !decrypt(&key, aad, &mut verifier)?.is_empty() {
                    return Err(integrity_error());
                }
                Ok(key)
            },
            |id| {
                let key = key_for(id, true)?;
                let verifier = encrypt(&key, Aad::from(check_aad(id)), new_envelope())?;
                Ok((key, verifier))
            },
        )?;
        Ok(Self {
            store,
            database_id,
            writer_id,
            key,
        })
    }

    /// Relinquish write ownership without removing any data. An already-opened
    /// replacement keeps its own ownership even if this instance closes late.
    pub(crate) fn close(&self) -> Result<()> {
        self.store.release_resume_writer(&self.writer_id)
    }

    pub(crate) fn put<T: Serialize + ?Sized>(&self, namespace: &str, id: &str, value: &T) -> Result<()> {
        self.store.commit_resume(&[self.seal(namespace, id, value)?])
    }

    pub(crate) fn get<T: DeserializeOwned>(&self, namespace: &str, id: &str) -> Result<Option<T>> {
        self.store
            .get_resume(namespace, id)?
            .map(|ciphertext| self.unseal(namespace, id, ciphertext))
            .transpose()
    }

    pub(crate) fn list<T: DeserializeOwned>(&self, namespace: &str) -> Result<Vec<(String, T)>> {
        self.store
            .list_resume(namespace)?
            .into_iter()
            .map(|(id, ciphertext)| {
                let value = self.unseal(namespace, &id, ciphertext)?;
                Ok((id, value))
            })
            .collect()
    }

    pub(crate) fn remove(&self, namespace: &str, id: &str) -> Result<()> {
        self.store
            .commit_resume(&[SealedResume::new(self.writer_id, namespace, id, None)])
    }

    pub(crate) fn seal<T: Serialize + ?Sized>(
        &self,
        namespace: &str,
        id: &str,
        value: &T,
    ) -> Result<SealedResume> {
        let mut buffer = new_envelope();
        serde_json::to_writer(&mut *buffer, value)
            .map_err(|_| CoreError::internal("could not encode restart state"))?;
        let ciphertext = encrypt(&self.key, self.entry_aad(namespace, id), buffer)?;
        Ok(SealedResume::new(self.writer_id, namespace, id, Some(ciphertext)))
    }

    fn unseal<T: DeserializeOwned>(&self, namespace: &str, id: &str, ciphertext: Vec<u8>) -> Result<T> {
        let mut buffer = Zeroizing::new(ciphertext);
        let plaintext = decrypt(&self.key, self.entry_aad(namespace, id), &mut buffer)?;
        serde_json::from_slice(plaintext)
            .map_err(|_| CoreError::internal("could not decode restart state"))
    }

    fn entry_aad(&self, namespace: &str, id: &str) -> Aad<Vec<u8>> {
        let mut bytes = Vec::with_capacity(
            ENTRY_DOMAIN.len() + self.database_id.len() + 8 + namespace.len() + id.len(),
        );
        bytes.extend_from_slice(ENTRY_DOMAIN);
        bytes.extend_from_slice(&self.database_id);
        // A length prefix distinguishes ("a", "bc") from ("ab", "c").
        bytes.extend_from_slice(&(namespace.len() as u64).to_be_bytes());
        bytes.extend_from_slice(namespace.as_bytes());
        bytes.extend_from_slice(id.as_bytes());
        Aad::from(bytes)
    }
}

fn check_aad(id: &[u8; 16]) -> [u8; CHECK_DOMAIN.len() + 16] {
    let mut bytes = [0; CHECK_DOMAIN.len() + 16];
    let (domain, database) = bytes.split_at_mut(CHECK_DOMAIN.len());
    domain.copy_from_slice(CHECK_DOMAIN);
    database.copy_from_slice(id);
    bytes
}

fn make_key(raw: &[u8; 32]) -> Result<LessSafeKey> {
    let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, raw)
        .map_err(|_| CoreError::internal("invalid restart key"))?;
    Ok(LessSafeKey::new(unbound))
}

fn fill_random(bytes: &mut [u8]) -> Result<()> {
    getrandom::fill(bytes).map_err(|_| CoreError::internal("restart storage randomness unavailable"))
}

fn integrity_error() -> CoreError {
    CoreError::internal("restart state authentication failed")
}

fn new_envelope() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(vec![0; NONCE_LEN])
}

fn encrypt<A: AsRef<[u8]>>(
    key: &LessSafeKey,
    aad: Aad<A>,
    mut envelope: Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>> {
    let mut nonce = [0; NONCE_LEN];
    fill_random(&mut nonce)?;
    envelope[..NONCE_LEN].copy_from_slice(&nonce);
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            aad,
            &mut envelope[NONCE_LEN..],
        )
        .map_err(|_| CoreError::internal("could not seal restart state"))?;
    envelope.extend_from_slice(tag.as_ref());
    Ok(std::mem::take(&mut *envelope))
}

fn decrypt<'a, A: AsRef<[u8]>>(
    key: &LessSafeKey,
    aad: Aad<A>,
    ciphertext: &'a mut [u8],
) -> Result<&'a [u8]> {
    let (nonce, body) = ciphertext
        .split_at_mut_checked(NONCE_LEN)
        .ok_or_else(integrity_error)?;
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| integrity_error())?;
    key.open_in_place(nonce, aad, body)
        .map(|value| &*value)
        .map_err(|_| integrity_error())
}

#[cfg(test)]
#[path = "resume_tests.rs"]
mod tests;
