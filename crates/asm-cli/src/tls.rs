//! TLS for the manager API (certificate pinning) and the proxy probe (proxy CA).

use asm_proto::crypto::{hex_encode, sha256};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Which manager certificate is acceptable.
#[derive(Debug, Clone)]
pub enum Pin {
    /// Only the certificate whose DER has this SHA-256.
    Fixed([u8; 32]),
    /// Pairing: the first certificate seen is recorded; every later handshake must
    /// present the same certificate.
    FirstSeen(Arc<Mutex<Option<[u8; 32]>>>),
}

impl Pin {
    /// A fresh first-seen pin.
    pub fn first_seen() -> Self {
        Pin::FirstSeen(Arc::new(Mutex::new(None)))
    }

    /// The pinned (or first seen) fingerprint, if any.
    pub fn fingerprint(&self) -> Option<[u8; 32]> {
        match self {
            Pin::Fixed(fp) => Some(*fp),
            Pin::FirstSeen(seen) => *seen.lock().unwrap_or_else(|e| e.into_inner()),
        }
    }
}

/// Accepts exactly the pinned end-entity certificate and still verifies the
/// handshake signature against it, so a replayed public certificate without its
/// private key fails.
#[derive(Debug)]
pub struct PinVerifier {
    pin: Pin,
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinVerifier {
    pub fn new(pin: Pin, provider: &CryptoProvider) -> Self {
        PinVerifier {
            pin,
            algorithms: provider.signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = sha256(end_entity.as_ref());
        let expected = match &self.pin {
            Pin::Fixed(fp) => *fp,
            Pin::FirstSeen(seen) => {
                let mut seen = seen.lock().unwrap_or_else(|e| e.into_inner());
                *seen.get_or_insert(got)
            }
        };
        if asm_proto::crypto::ct_eq(&got, &expected) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "manager certificate {} does not match the pinned certificate {}",
                hex_encode(&got),
                hex_encode(&expected)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// rustls client configuration that trusts only the pinned manager certificate.
pub fn pinned_config(pin: Pin) -> ClientConfig {
    let provider = provider();
    let verifier = Arc::new(PinVerifier::new(pin, &provider));
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

/// Blocking HTTP client for the manager API: pinned TLS, never uses a proxy.
pub fn manager_client(pin: Pin, timeout: Duration) -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .tls_backend_preconfigured(pinned_config(pin))
        .no_proxy()
        .connect_timeout(Duration::from_secs(10))
        .timeout(timeout)
        .user_agent(concat!("asm/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("building the HTTP client: {}", error_chain(&e)))
}

/// Blocking HTTP client that goes through `proxy_url` and trusts only the proxy CA
/// (`ca_pem`), as an agent tool would after `asm proxy-info`.
pub fn proxy_probe_client(
    proxy_url: &str,
    ca_pem: &[u8],
) -> Result<reqwest::blocking::Client, String> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca_pem) {
        let cert = cert.map_err(|e| format!("reading the proxy CA: {e}"))?;
        roots
            .add(cert)
            .map_err(|e| format!("reading the proxy CA: {e}"))?;
    }
    if roots.is_empty() {
        return Err("the proxy CA file holds no certificate".into());
    }
    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let proxy =
        reqwest::Proxy::all(proxy_url).map_err(|e| format!("proxy URL {proxy_url}: {e}"))?;
    reqwest::blocking::Client::builder()
        .tls_backend_preconfigured(config)
        .proxy(proxy)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| format!("building the HTTP client: {}", error_chain(&e)))
}

/// Parse the first certificate of a PEM file to DER.
pub fn pem_to_der(pem: &[u8]) -> Option<Vec<u8>> {
    CertificateDer::pem_slice_iter(pem)
        .next()?
        .ok()
        .map(|c| c.as_ref().to_vec())
}

/// `err` and all its sources, joined with `: `.
pub fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut out = err.to_string();
    let mut cur = err.source();
    while let Some(e) = cur {
        let s = e.to_string();
        if !out.contains(&s) {
            out.push_str(": ");
            out.push_str(&s);
        }
        cur = e.source();
    }
    out
}

/// True when the error was caused by TLS (handshake, certificate, signature).
pub fn is_tls_error(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if e.downcast_ref::<rustls::Error>().is_some() {
            return true;
        }
        if let Some(io) = e.downcast_ref::<std::io::Error>()
            && io
                .get_ref()
                .is_some_and(|inner| inner.downcast_ref::<rustls::Error>().is_some())
        {
            return true;
        }
        cur = e.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;
    use rustls::{ServerConfig, ServerConnection, StreamOwned};
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[derive(Debug)]
    struct FixedResolver(Arc<CertifiedKey>);
    impl ResolvesServerCert for FixedResolver {
        fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    /// A one-shot HTTPS server presenting `cert` and signing with `key` (which may not
    /// belong to `cert`). Returns the port.
    fn serve(
        cert: Vec<u8>,
        key: Vec<u8>,
        versions: &'static [&'static rustls::SupportedProtocolVersion],
    ) -> u16 {
        let provider = provider();
        let signer =
            rustls::crypto::ring::sign::any_supported_type(&PrivateKeyDer::Pkcs8(key.into()))
                .unwrap();
        let ck = Arc::new(CertifiedKey::new(vec![CertificateDer::from(cert)], signer));
        let config = Arc::new(
            ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(versions)
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(FixedResolver(ck))),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let conn = ServerConnection::new(config.clone()).unwrap();
                let mut tls = StreamOwned::new(conn, stream);
                let mut buf = [0u8; 4096];
                if tls.read(&mut buf).is_ok() {
                    let _ = tls.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    );
                    let _ = tls.flush();
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                }
            }
        });
        port
    }

    fn cert_and_key() -> (Vec<u8>, Vec<u8>) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        (ck.cert.der().to_vec(), ck.signing_key.serialize_der())
    }

    fn get(port: u16, pin: Pin) -> Result<String, String> {
        let client = manager_client(pin, Duration::from_secs(10))?;
        client
            .get(format!("https://127.0.0.1:{port}/"))
            .send()
            .and_then(|r| r.text())
            .map_err(|e| error_chain(&e))
    }

    const TLS13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
    const TLS12: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];

    #[test]
    fn pinned_certificate_with_its_key_succeeds() {
        for versions in [TLS13, TLS12] {
            let (cert, key) = cert_and_key();
            let pin = Pin::Fixed(sha256(&cert));
            let port = serve(cert, key, versions);
            assert_eq!(get(port, pin).unwrap(), "ok");
        }
    }

    #[test]
    fn pinned_certificate_with_another_key_fails() {
        for versions in [TLS13, TLS12] {
            let (cert, _) = cert_and_key();
            let other_key = rcgen::KeyPair::generate().unwrap().serialize_der();
            let pin = Pin::Fixed(sha256(&cert));
            let port = serve(cert, other_key, versions);
            let err = get(port, pin).unwrap_err();
            assert!(err.contains("BadSignature"), "{err}");
        }
    }

    #[test]
    fn unpinned_certificate_fails() {
        let (cert, key) = cert_and_key();
        let port = serve(cert, key, TLS13);
        let err = get(port, Pin::Fixed([7; 32])).unwrap_err();
        assert!(
            err.contains("does not match the pinned certificate"),
            "{err}"
        );
    }

    #[test]
    fn first_seen_pin_rejects_a_changed_certificate() {
        let (cert_a, key_a) = cert_and_key();
        let (cert_b, key_b) = cert_and_key();
        let fp_a = sha256(&cert_a);
        let port_a = serve(cert_a, key_a, TLS13);
        let port_b = serve(cert_b, key_b, TLS13);
        let pin = Pin::first_seen();
        assert_eq!(get(port_a, pin.clone()).unwrap(), "ok");
        assert_eq!(pin.fingerprint(), Some(fp_a));
        let err = get(port_b, pin.clone()).unwrap_err();
        assert!(
            err.contains("does not match the pinned certificate"),
            "{err}"
        );
    }
}
