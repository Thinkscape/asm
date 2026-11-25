//! OpenSSH user certificates (`ssh-ed25519-cert-v01@openssh.com`), built with `ssh-key`.

use asm_proto::crypto::random_bytes;
use asm_proto::ssh::b64_encode;
use ssh_key::certificate::{Builder, CertType};
use ssh_key::public::{Ed25519PublicKey, KeyData};

use super::keys::SshKey;
use crate::error::{CoreError, Result};

pub(crate) const CERT_TYPE: &str = "ssh-ed25519-cert-v01@openssh.com";

pub(crate) struct CertSpec<'a> {
    pub key_id: &'a str,
    pub principals: &'a [String],
    pub valid_after: u64,
    pub valid_before: u64,
    pub force_command: Option<&'a str>,
    pub permit_pty: bool,
}

/// The certificate blob for `subject_pk`, signed by `ca`.
pub(crate) fn build_user_cert(ca: &SshKey, subject_pk: &[u8; 32], spec: &CertSpec<'_>) -> Result<Vec<u8>> {
    let failed = |e: ssh_key::Error| CoreError::internal(format!("building the SSH certificate: {e}"));
    let mut builder = Builder::new(random_bytes::<32>().to_vec(), KeyData::Ed25519(Ed25519PublicKey(*subject_pk)),
        spec.valid_after, spec.valid_before).map_err(failed)?;
    builder.serial(u64::from_be_bytes(random_bytes::<8>())).map_err(failed)?
        .key_id(spec.key_id).map_err(failed)?
        .cert_type(CertType::User).map_err(failed)?;
    for principal in spec.principals {
        builder.valid_principal(principal.as_str()).map_err(failed)?;
    }
    if let Some(command) = spec.force_command {
        builder.critical_option("force-command", command).map_err(failed)?;
    }
    if spec.permit_pty {
        builder.extension("permit-pty", "").map_err(failed)?;
    }
    builder.sign(&ca.private_key()).map_err(failed)?.to_bytes().map_err(failed)
}

/// `ssh-ed25519-cert-v01@openssh.com <b64> <comment>`.
pub(crate) fn cert_line(blob: &[u8], comment: &str) -> String {
    format!("{CERT_TYPE} {} {comment}", b64_encode(blob))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    const LEASE: &str = "00000000-0000-4000-8000-000000000001";

    fn keygen_list(blob: &[u8], key_id: &str) -> String {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lease-cert.pub");
        std::fs::write(&path, format!("{}\n", cert_line(blob, key_id))).unwrap();
        let out = Command::new("/usr/bin/ssh-keygen").arg("-L").arg("-f").arg(&path).output().unwrap();
        assert!(out.status.success(), "ssh-keygen -L failed: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap()
    }

    fn build(ca: &SshKey, key_id: &str, principal: &str, force_command: Option<&str>, permit_pty: bool) -> Vec<u8> {
        let subject = SshKey::generate();
        build_user_cert(ca, &subject.public_key(), &CertSpec {
            key_id, principals: &[principal.to_owned()], valid_after: 1_700_000_000, valid_before: 1_700_003_600,
            force_command, permit_pty,
        }).unwrap()
    }

    #[test]
    fn ssh_keygen_reads_privileged_restricted_and_cleanup_certificates() {
        let ca = SshKey::generate();
        let key_id = format!("asm-lease-{LEASE}");
        let command = format!("asm-shell lease={LEASE} until=1700003600");
        let privileged = build(&ca, &key_id, "asm-0123abcd-privileged", Some(&command), true);
        let text = keygen_list(&privileged, &key_id);
        assert!(text.contains("Type: ssh-ed25519-cert-v01@openssh.com user certificate"), "{text}");
        assert!(text.contains(&format!("Key ID: \"{key_id}\"")), "{text}");
        assert!(text.contains("asm-0123abcd-privileged"), "{text}");
        assert!(text.contains(&format!("force-command {command}")), "{text}");
        assert!(text.contains("permit-pty"), "{text}");
        for absent in ["source-address", "permit-port-forwarding", "permit-agent-forwarding", "permit-X11-forwarding",
            "permit-user-rc"]
        {
            assert!(!text.contains(absent), "{absent}: {text}");
        }
        assert!(text.contains(&ca.fingerprint()), "{text}");

        let command = format!("asm-grant lease={LEASE} until=1700003600 logs:web.service restart:web.service");
        let restricted = build(&ca, &key_id, "asm-0123abcd-restricted", Some(&command), false);
        let text = keygen_list(&restricted, &key_id);
        assert!(text.contains("asm-0123abcd-restricted"), "{text}");
        assert!(text.contains(&format!("force-command {command}")), "{text}");
        assert!(!text.contains("permit-pty"), "{text}");

        let key_id = "asm-cleanup-00000000-0000-4000-8000-000000000002";
        let cleanup = build(&ca, key_id, "asm-0123abcd-cleanup", None, false);
        let text = keygen_list(&cleanup, key_id);
        assert!(text.contains("Key ID: \"asm-cleanup-"), "{text}");
        assert!(text.contains("asm-0123abcd-cleanup"), "{text}");
        assert!(!text.contains("force-command") && !text.contains("permit-"), "{text}");
    }
}
