//! Self-signed ECDSA P-256 certificate of the manager API (`<data>/tls/`). Clients pin the
//! SHA-256 of its DER encoding.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::{CoreError, Result};

#[derive(Clone)]
pub struct ServerCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: Vec<u8>,
    /// SHA-256 of `cert_der`.
    pub sha256: [u8; 32],
}

impl std::fmt::Debug for ServerCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerCert")
            .field("sha256", &asm_proto::crypto::hex_encode(&self.sha256))
            .finish()
    }
}

const CERT_FILE: &str = "manager.crt";
const KEY_FILE: &str = "manager.key";

fn write_private(path: &Path, data: &str) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(data.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

impl ServerCert {
    /// Load `<tls>/manager.crt` + `manager.key`, or create both when either is missing.
    pub fn load_or_create(tls_dir: &Path) -> Result<Self> {
        let cert_path = tls_dir.join(CERT_FILE);
        let key_path = tls_dir.join(KEY_FILE);
        if cert_path.exists() && key_path.exists() {
            let cert_pem = std::fs::read_to_string(&cert_path)?;
            let key_pem = std::fs::read_to_string(&key_path)?;
            return Self::from_pem(cert_pem, key_pem);
        }
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| CoreError::internal(format!("tls key: {e}")))?;
        let mut params =
            rcgen::CertificateParams::new(vec!["asm-manager".to_string(), "localhost".to_string()])
                .map_err(|e| CoreError::internal(format!("tls params: {e}")))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Agents Secrets Manager");
        let cert = params
            .self_signed(&key)
            .map_err(|e| CoreError::internal(format!("tls cert: {e}")))?;
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();
        write_private(&key_path, &key_pem)?;
        write_private(&cert_path, &cert_pem)?;
        Self::from_pem(cert_pem, key_pem)
    }

    fn from_pem(cert_pem: String, key_pem: String) -> Result<Self> {
        let der = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .map_err(|e| CoreError::internal(format!("tls cert pem: {e}")))?;
        PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .map_err(|e| CoreError::internal(format!("tls key pem: {e}")))?;
        let cert_der = der.to_vec();
        let sha256 = asm_proto::pairing::cert_fingerprint(&cert_der);
        Ok(Self {
            cert_pem,
            key_pem,
            cert_der,
            sha256,
        })
    }

    pub fn sha256_hex(&self) -> String {
        asm_proto::crypto::hex_encode(&self.sha256)
    }

    /// rustls server config (ring provider) presenting this certificate.
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>> {
        let key = PrivateKeyDer::from_pem_slice(self.key_pem.as_bytes())
            .map_err(|e| CoreError::internal(format!("tls key pem: {e}")))?;
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| CoreError::internal(format!("tls: {e}")))?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(self.cert_der.clone())], key)
        .map_err(|e| CoreError::internal(format!("tls: {e}")))?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(cfg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_reload_keeps_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let a = ServerCert::load_or_create(dir.path()).unwrap();
        let b = ServerCert::load_or_create(dir.path()).unwrap();
        assert_eq!(a.sha256, b.sha256);
        assert_eq!(a.sha256, asm_proto::crypto::sha256(&a.cert_der));
        a.server_config().unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
