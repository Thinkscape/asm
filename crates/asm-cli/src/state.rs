//! Pairing state on the agent machine: `${XDG_CONFIG_HOME:-~/.config}/asm/`
//! holding `host.json` (0600), `ca.crt` (proxy CA) and `ca-bundle.crt`.

use crate::error::CliError;
use crate::files::{ensure_private_dir, write_file_atomic};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// System CA bundles, first existing wins.
const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/etc/ssl/ca-bundle.pem",
];

/// Contents of `host.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostState {
    pub manager_url: String,
    /// Lowercase hex SHA-256 of the manager certificate (DER).
    pub cert_sha256: String,
    pub host_id: String,
    pub token: String,
    pub paired_at: String,
}

impl HostState {
    /// The pinned fingerprint.
    pub fn pin(&self) -> Result<[u8; 32], CliError> {
        asm_proto::crypto::hex_decode_array(&self.cert_sha256)
            .ok_or_else(|| CliError::failure("host.json holds an invalid cert_sha256; pair again"))
    }

    /// Host part of `manager_url` (without brackets for IPv6).
    pub fn manager_host(&self) -> String {
        let rest = self
            .manager_url
            .split_once("://")
            .map_or(self.manager_url.as_str(), |(_, r)| r);
        let authority = rest.split('/').next().unwrap_or(rest);
        if let Some(v6) = authority.strip_prefix('[') {
            return v6.split(']').next().unwrap_or(v6).to_owned();
        }
        authority
            .rsplit_once(':')
            .map_or(authority, |(h, _)| h)
            .to_owned()
    }
}

/// The CLI's configuration directory.
pub fn config_dir() -> Result<PathBuf, CliError> {
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        let p = PathBuf::from(x);
        if p.is_absolute() {
            return Ok(p.join("asm"));
        }
    }
    Ok(home_dir()?.join(".config").join("asm"))
}

/// `$HOME`, else the passwd entry of the current user.
pub fn home_dir() -> Result<PathBuf, CliError> {
    if let Some(h) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(h));
    }
    crate::hostinfo::passwd_home()
        .ok_or_else(|| CliError::failure("cannot determine the home directory"))
}

pub fn host_json_path() -> Result<PathBuf, CliError> {
    Ok(config_dir()?.join("host.json"))
}

pub fn ca_path() -> Result<PathBuf, CliError> {
    Ok(config_dir()?.join("ca.crt"))
}

pub fn ca_bundle_path() -> Result<PathBuf, CliError> {
    Ok(config_dir()?.join("ca-bundle.crt"))
}

/// Load `host.json`; `Ok(None)` when it does not exist.
pub fn load() -> Result<Option<HostState>, CliError> {
    let path = host_json_path()?;
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|e| {
            CliError::failure(format!("{} is not valid: {e}; pair again", path.display()))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CliError::failure(format!(
            "reading {}: {e}",
            path.display()
        ))),
    }
}

/// Load `host.json` or fail with exit 6 ("not paired").
pub fn require() -> Result<HostState, CliError> {
    load()?.ok_or_else(|| CliError::unauthorized("not paired; run asm pair <manager-host>"))
}

/// Write `host.json` (0600).
pub fn save(state: &HostState) -> Result<(), CliError> {
    let dir = config_dir()?;
    ensure_private_dir(&dir)?;
    let json = serde_json::to_vec_pretty(state).expect("HostState serializes");
    write_file_atomic(&dir, "host.json", &json).map(|_| ())
}

/// Write `ca.crt` and `ca-bundle.crt` (first existing system bundle plus the
/// proxy CA; the CA alone when no system bundle exists).
pub fn write_ca_files(ca_pem: &str) -> Result<(), CliError> {
    let dir = config_dir()?;
    ensure_private_dir(&dir)?;
    let mut ca = ca_pem.to_owned();
    if !ca.ends_with('\n') {
        ca.push('\n');
    }
    write_file_atomic(&dir, "ca.crt", ca.as_bytes())?;
    let mut bundle = system_bundle().unwrap_or_default();
    if !bundle.is_empty() && !bundle.ends_with(b"\n") {
        bundle.push(b'\n');
    }
    bundle.extend_from_slice(ca.as_bytes());
    write_file_atomic(&dir, "ca-bundle.crt", &bundle).map(|_| ())
}

fn system_bundle() -> Option<Vec<u8>> {
    SYSTEM_BUNDLES.iter().find_map(|p| std::fs::read(p).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_host_forms() {
        let mut s = HostState {
            manager_url: "https://mac.tail.ts.net:7411".into(),
            cert_sha256: String::new(),
            host_id: String::new(),
            token: String::new(),
            paired_at: String::new(),
        };
        assert_eq!(s.manager_host(), "mac.tail.ts.net");
        s.manager_url = "https://[fd00::1]:7411".into();
        assert_eq!(s.manager_host(), "fd00::1");
        s.manager_url = "https://10.0.0.2:7411".into();
        assert_eq!(s.manager_host(), "10.0.0.2");
    }
}
