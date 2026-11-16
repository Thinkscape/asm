//! `asm proxy-info` and `asm doctor`.

use crate::api::Api;
use crate::error::CliError;
use crate::files::{SecretsDir, write_file_atomic};
use crate::requests::Session;
use crate::state::{self, HostState};
use crate::tls::{Pin, error_chain, is_tls_error, pem_to_der, proxy_probe_client};
use asm_proto::crypto::sha256_hex;
use asm_proto::error::ErrorCode;
use asm_proto::wire::{HealthResponse, MANAGER_NAME, ProxyInfo};
use serde::Serialize;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

/// `host` in URL authority form (IPv6 in brackets).
fn authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// True when `host:port` accepts a TCP connection within 1 s.
fn accepts_tcp(host: &str, port: u16) -> bool {
    let Ok(addrs) = (host, port).to_socket_addrs() else {
        return false;
    };
    addrs
        .into_iter()
        .any(|a| TcpStream::connect_timeout(&a, Duration::from_secs(1)).is_ok())
}

/// Single-quote for POSIX shells.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Fetch the proxy CA, check it against `ca_sha256`, write `ca.crt` / `ca-bundle.crt`.
fn refresh_ca(api: &Api, info: &ProxyInfo) -> Result<(), CliError> {
    let pem = api.get_bytes("/ca.crt")?;
    let der = pem_to_der(&pem)
        .ok_or_else(|| CliError::failure("the manager's proxy CA is not a PEM certificate"))?;
    if !sha256_hex(&der).eq_ignore_ascii_case(&info.ca_sha256) {
        return Err(CliError::failure(
            "the proxy CA does not match the fingerprint the manager reported",
        ));
    }
    let pem =
        String::from_utf8(pem).map_err(|_| CliError::failure("the proxy CA is not PEM text"))?;
    state::write_ca_files(&pem)
}

/// Environment lines for the recommended proxy.
fn exports(host: &HostState, proxy_http: &str) -> Result<Vec<(&'static str, String)>, CliError> {
    let bundle = state::ca_bundle_path()?.to_string_lossy().into_owned();
    let ca = state::ca_path()?.to_string_lossy().into_owned();
    Ok(vec![
        ("HTTPS_PROXY", proxy_http.to_owned()),
        ("HTTP_PROXY", proxy_http.to_owned()),
        ("ALL_PROXY", proxy_http.to_owned()),
        ("NO_PROXY", host.manager_host()),
        ("SSL_CERT_FILE", bundle.clone()),
        ("REQUESTS_CA_BUNDLE", bundle.clone()),
        ("CURL_CA_BUNDLE", bundle.clone()),
        ("GIT_SSL_CAINFO", bundle),
        ("NODE_EXTRA_CA_CERTS", ca),
    ])
}

#[derive(Serialize)]
struct JsonProxy {
    hint: String,
    http: String,
    socks5h: String,
    recommended: bool,
}

#[derive(Serialize)]
struct JsonProxyInfo {
    port: u16,
    ca_sha256: String,
    proxies: Vec<JsonProxy>,
    recommended: Option<String>,
    env: serde_json::Map<String, serde_json::Value>,
}

pub fn proxy_info(json: bool) -> Result<(), CliError> {
    let s = Session::open()?;
    s.warn_secrets();
    s.sync_leases()?;
    let info: ProxyInfo = s.api.get("/proxy-info")?;
    refresh_ca(&s.api, &info)?;
    let recommended = info.hints.iter().position(|h| accepts_tcp(h, info.port));
    let proxies: Vec<JsonProxy> = info
        .hints
        .iter()
        .enumerate()
        .map(|(i, h)| JsonProxy {
            hint: h.clone(),
            http: format!("http://{}", authority(h, info.port)),
            socks5h: format!("socks5h://{}", authority(h, info.port)),
            recommended: Some(i) == recommended,
        })
        .collect();
    let env = match recommended {
        Some(i) => exports(&s.host, &proxies[i].http)?,
        None => Vec::new(),
    };
    if json {
        let j = JsonProxyInfo {
            port: info.port,
            ca_sha256: info.ca_sha256.clone(),
            recommended: recommended.map(|i| proxies[i].http.clone()),
            env: env
                .iter()
                .map(|(k, v)| ((*k).to_owned(), serde_json::Value::String(v.clone())))
                .collect(),
            proxies,
        };
        println!("{}", serde_json::to_string_pretty(&j).expect("serializes"));
    } else {
        for p in &proxies {
            let mark = if p.recommended { " (recommended)" } else { "" };
            println!("{}{mark}", p.http);
            println!("{}{mark}", p.socks5h);
        }
        for (k, v) in &env {
            println!("export {k}={}", shell_quote(v));
        }
    }
    if recommended.is_none() {
        return Err(CliError::failure(format!(
            "no proxy hint accepts TCP connections on port {}; check the network path to the manager's Mac",
            info.port
        )));
    }
    Ok(())
}

/// Collects doctor lines; tracks whether anything failed.
struct Report {
    failed: bool,
}

impl Report {
    fn ok(&mut self, check: &str, detail: impl AsRef<str>) {
        println!("ok {check}: {}", detail.as_ref());
    }
    fn warn(&mut self, check: &str, detail: impl AsRef<str>) {
        println!("warn {check}: {}", detail.as_ref());
    }
    fn fail(&mut self, check: &str, detail: impl AsRef<str>) {
        self.failed = true;
        println!("FAIL {check}: {}", detail.as_ref());
    }
}

pub fn doctor(probe_url: &str) -> Result<(), CliError> {
    let mut r = Report { failed: false };

    // 1. paired
    let host = match state::load() {
        Ok(Some(h)) => match h.pin() {
            Ok(_) => {
                r.ok(
                    "paired",
                    format!("host {} with manager {}", h.host_id, h.manager_url),
                );
                Some(h)
            }
            Err(e) => {
                r.fail("paired", e.message);
                None
            }
        },
        Ok(None) => {
            let path = state::host_json_path()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            r.fail(
                "paired",
                format!("not paired ({path} missing); run asm pair <manager-host>"),
            );
            None
        }
        Err(e) => {
            r.fail("paired", e.message);
            None
        }
    };

    // 2. manager reachable and pin matches
    let api = host.as_ref().and_then(|h| Api::for_host(h).ok());
    let reachable = match (&host, &api) {
        (Some(h), Some(api)) => {
            let unauth = Api::new(
                h.manager_url.clone(),
                Pin::Fixed(h.pin().expect("checked")),
                None,
            );
            match unauth.as_ref().map(|a| a.try_get("/health")) {
                Ok(Ok(resp)) => match resp.json::<HealthResponse>() {
                    Ok(hr) if hr.name == MANAGER_NAME => {
                        r.ok(
                            "manager",
                            format!(
                                "{} reachable, certificate matches the pin (version {})",
                                api.base(),
                                hr.version
                            ),
                        );
                        true
                    }
                    _ => {
                        r.fail(
                            "manager",
                            format!("{} does not answer like an asm manager", api.base()),
                        );
                        false
                    }
                },
                Ok(Err(e)) if is_tls_error(&e) => {
                    r.fail(
                        "manager",
                        format!(
                            "{}: TLS failed, the certificate does not match the pin: {}",
                            api.base(),
                            error_chain(&e)
                        ),
                    );
                    false
                }
                Ok(Err(e)) => {
                    r.fail(
                        "manager",
                        format!("{} unreachable: {}", api.base(), error_chain(&e)),
                    );
                    false
                }
                Err(e) => {
                    r.fail("manager", e.message.clone());
                    false
                }
            }
        }
        _ => false,
    };

    // 3. token accepted (also syncs lease files)
    let secrets = SecretsDir::open_default();
    if let Ok(d) = &secrets {
        let _ = d.remove_expired();
    }
    let token_ok = match (&host, &api) {
        (Some(h), Some(api)) if reachable => {
            let session = Session {
                host: h.clone(),
                api: Api::for_host(h)?,
                secrets: secrets.clone(),
            };
            match session.sync_leases() {
                Ok(_) => {
                    r.ok("token", "accepted");
                    true
                }
                Err(e) if e.code == Some(ErrorCode::Unauthorized) => {
                    r.fail(
                        "token",
                        format!(
                            "rejected by {}; the host may have been revoked, pair again",
                            api.base()
                        ),
                    );
                    false
                }
                Err(e) => {
                    r.fail("token", e.message);
                    false
                }
            }
        }
        _ => false,
    };

    // 4. secrets directory usable
    match &secrets {
        Ok(d) => match write_file_atomic(d.root(), ".doctor-probe", b"ok") {
            Ok(p) => {
                let _ = std::fs::remove_file(p);
                r.ok("secrets directory", d.root().display().to_string());
            }
            Err(e) => r.fail("secrets directory", e.message),
        },
        Err(e) => r.fail("secrets directory", e.message.clone()),
    }

    if host.is_none() {
        return finish(r);
    }

    // 5. CA files present
    let info: Option<ProxyInfo> = match &api {
        Some(api) if token_ok => api.get("/proxy-info").ok(),
        _ => None,
    };
    let ca_path = state::ca_path()?;
    let bundle_path = state::ca_bundle_path()?;
    let ca_ok = check_ca_files(&mut r, &ca_path, &bundle_path, info.as_ref());

    // 6. each hint accepts TCP
    let mut recommended: Option<String> = None;
    if let Some(info) = &info {
        if info.hints.is_empty() {
            r.fail(
                "proxy",
                "the manager lists no proxy hostname hints; add one in Proxy settings",
            );
        }
        for h in &info.hints {
            let url = format!("http://{}", authority(h, info.port));
            if accepts_tcp(h, info.port) {
                r.ok("proxy", format!("{url} accepts TCP"));
                recommended.get_or_insert(url);
            } else {
                r.warn("proxy", format!("{url} does not accept TCP connections"));
            }
        }
        if !info.hints.is_empty() && recommended.is_none() {
            r.fail("proxy", "no proxy hint is reachable");
        }
    }

    // 7. HTTPS probe through the recommended proxy, verified against ca.crt
    if let (Some(proxy), true) = (&recommended, ca_ok) {
        match std::fs::read(&ca_path)
            .map_err(|e| e.to_string())
            .and_then(|pem| proxy_probe_client(proxy, &pem))
        {
            Ok(client) => match client.get(probe_url).send() {
                Ok(resp) => r.ok(
                    "probe",
                    format!(
                        "{probe_url} through {proxy}: HTTP {}, certificate verified against ca.crt",
                        resp.status().as_u16()
                    ),
                ),
                Err(e) if is_tls_error(&e) => r.fail(
                    "probe",
                    format!(
                        "{probe_url} through {proxy}: TLS verification failed: {}",
                        error_chain(&e)
                    ),
                ),
                Err(e) => r.warn(
                    "probe",
                    format!("{probe_url} through {proxy}: {}", error_chain(&e)),
                ),
            },
            Err(e) => r.fail("probe", e),
        }
    }
    finish(r)
}

fn check_ca_files(r: &mut Report, ca: &Path, bundle: &Path, info: Option<&ProxyInfo>) -> bool {
    let pem = match std::fs::read(ca) {
        Ok(p) => p,
        Err(_) => {
            r.fail(
                "CA files",
                format!("{} missing; run asm proxy-info", ca.display()),
            );
            return false;
        }
    };
    let Some(der) = pem_to_der(&pem) else {
        r.fail(
            "CA files",
            format!(
                "{} is not a PEM certificate; run asm proxy-info",
                ca.display()
            ),
        );
        return false;
    };
    if !bundle.exists() {
        r.fail(
            "CA files",
            format!("{} missing; run asm proxy-info", bundle.display()),
        );
        return false;
    }
    match info {
        Some(i) if !sha256_hex(&der).eq_ignore_ascii_case(&i.ca_sha256) => {
            r.fail(
                "CA files",
                format!(
                    "{} is not the manager's current proxy CA; run asm proxy-info",
                    ca.display()
                ),
            );
            false
        }
        _ => {
            r.ok(
                "CA files",
                format!("{} and {}", ca.display(), bundle.display()),
            );
            true
        }
    }
}

fn finish(r: Report) -> Result<(), CliError> {
    if r.failed {
        Err(CliError::new(asm_proto::error::EXIT_FAILURE, String::new()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_and_authority() {
        assert_eq!(shell_quote("http://h:7412"), "'http://h:7412'");
        assert_eq!(shell_quote("a'b"), r"'a'\''b'");
        assert_eq!(authority("fd00::1", 7412), "[fd00::1]:7412");
        assert_eq!(authority("mac.ts.net", 7412), "mac.ts.net:7412");
    }
}
