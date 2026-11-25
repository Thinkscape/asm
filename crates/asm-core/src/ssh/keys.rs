//! Ed25519 keys in OpenSSH wire form.

use std::fmt;

use asm_proto::ssh::{b64_decode, b64_encode, put_string};
use ed25519_dalek::{Signer, SigningKey};
use ssh_key::private::Ed25519Keypair;
use ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

pub(crate) const ED25519: &str = "ssh-ed25519";

pub(crate) struct SshKey(SigningKey);

impl SshKey {
    pub(crate) fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *seed).expect("operating system random number generator failed");
        Self::from_seed(&seed)
    }

    pub(crate) fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// Standard base64 of the 32-byte seed, for sealed storage only.
    pub(crate) fn seed_b64(&self) -> Zeroizing<String> {
        Zeroizing::new(b64_encode(self.0.as_bytes()))
    }

    pub(crate) fn from_seed_b64(text: &str) -> Result<Self> {
        let bytes = Zeroizing::new(b64_decode(text).ok_or_else(|| CoreError::internal("invalid stored SSH key"))?);
        let seed: &[u8; 32] = bytes.as_slice().try_into().map_err(|_| CoreError::internal("invalid stored SSH key"))?;
        Ok(Self::from_seed(seed))
    }

    pub(crate) fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub(crate) fn ssh_public_key(&self) -> PublicKey {
        PublicKey::from(KeyData::Ed25519(Ed25519PublicKey(self.public_key())))
    }

    pub(crate) fn private_key(&self) -> PrivateKey {
        Ed25519Keypair::from_seed(self.0.as_bytes()).into()
    }

    /// The private key in OpenSSH format, for a certificate run's `id` file.
    pub(crate) fn private_openssh(&self) -> Result<Zeroizing<String>> {
        self.private_key().to_openssh(LineEnding::LF)
            .map_err(|e| CoreError::internal(format!("encoding the SSH key: {e}")))
    }

    /// `ssh-ed25519 <b64>`.
    pub(crate) fn openssh_line(&self) -> String {
        self.ssh_public_key().to_openssh().expect("an Ed25519 public key always encodes")
    }

    /// The SSH signature blob `string "ssh-ed25519" ‖ string sig`.
    pub(crate) fn sign_blob(&self, data: &[u8]) -> Vec<u8> {
        let signature = self.0.sign(data).to_bytes();
        let mut out = Vec::with_capacity(4 + ED25519.len() + 4 + signature.len());
        put_string(&mut out, ED25519.as_bytes());
        put_string(&mut out, &signature);
        out
    }

    /// `SHA256:<base64 without padding>` of the public key blob, as OpenSSH prints it.
    pub(crate) fn fingerprint(&self) -> String {
        self.ssh_public_key().fingerprint(HashAlg::Sha256).to_string()
    }
}

impl fmt::Debug for SshKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SshKey({})", self.fingerprint())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[test]
    fn signs_in_ssh_form_and_round_trips_seed() {
        let key = SshKey::generate();
        let again = SshKey::from_seed_b64(&key.seed_b64()).unwrap();
        assert_eq!(key.public_key(), again.public_key());
        let blob = key.sign_blob(b"payload");
        let mut r = asm_proto::ssh::Reader::new(&blob);
        assert_eq!(r.string().unwrap(), ED25519.as_bytes());
        let sig: [u8; 64] = r.string().unwrap().try_into().unwrap();
        assert!(r.is_empty());
        VerifyingKey::from_bytes(&key.public_key()).unwrap()
            .verify(b"payload", &Signature::from_bytes(&sig)).unwrap();
        assert!(!format!("{key:?}").contains(&*key.seed_b64()));
    }

    #[test]
    fn public_forms_match_openssh() {
        let key = SshKey::generate();
        let mut expected = Vec::new();
        put_string(&mut expected, ED25519.as_bytes());
        put_string(&mut expected, &key.public_key());
        assert_eq!(key.ssh_public_key().to_bytes().unwrap(), expected);
        assert_eq!(key.openssh_line(), format!("ssh-ed25519 {}", b64_encode(&expected)));
        let digest = asm_proto::crypto::sha256(&expected);
        assert_eq!(key.fingerprint(), format!("SHA256:{}", STANDARD_NO_PAD.encode(digest)));
        let pem = key.private_openssh().unwrap();
        assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"), "{}", &*pem);
        let parsed = PrivateKey::from_openssh(pem.as_bytes()).unwrap();
        assert_eq!(parsed.public_key().key_data(), key.ssh_public_key().key_data());
    }
}
