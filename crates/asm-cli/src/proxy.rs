//! `asm proxy-info`, `asm proxy-env` and `asm doctor`.

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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// `host` in URL authority form (IPv6 in brackets).
pub(crate) fn authority(host: &str, port: u16) -> String {
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

/// This host's proxy-authentication password: [`asm_proto::crypto::proxy_password`] of
/// the SHA-256 of its bearer token.
pub(crate) fn proxy_password(host: &HostState) -> String {
    asm_proto::crypto::proxy_password(&asm_proto::crypto::sha256(host.token.as_bytes()))
}

/// `Proxy-Authorization` value with this host's proxy credentials (`Basic`).
pub(crate) fn proxy_authorization(host: &HostState) -> String {
    use base64::Engine as _;
    let creds = format!("{}:{}", host.host_id, proxy_password(host));
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(creds))
}

/// Percent-encode a URL userinfo component (everything but RFC 3986 unreserved).
fn userinfo_escape(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            b => format!("%{b:02X}"),
        })
        .collect()
}

/// `scheme://authority`, with this host's credentials as userinfo when `auth` is set.
fn proxy_url(scheme: &str, host: &HostState, authority: &str, auth: bool) -> String {
    if auth {
        format!(
            "{scheme}://{}:{}@{authority}",
            userinfo_escape(&host.host_id),
            proxy_password(host)
        )
    } else {
        format!("{scheme}://{authority}")
    }
}

/// Environment lines for the recommended proxy (hint `i`); the proxy URL carries this
/// host's credentials when the manager requires proxy authentication.
fn exports(host: &HostState, r: &Resolved, i: usize) -> Result<Vec<(&'static str, String)>, CliError> {
    let proxy_http = proxy_url("http", host, &authority(&r.info.hints[i], r.info.port), r.info.proxy_auth);
    let bundle = state::ca_bundle_path()?.to_string_lossy().into_owned();
    let ca = state::ca_path()?.to_string_lossy().into_owned();
    Ok(vec![
        ("HTTPS_PROXY", proxy_http.clone()),
        ("HTTP_PROXY", proxy_http.clone()),
        ("ALL_PROXY", proxy_http),
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
    ca_file: String,
    ca_bundle_file: String,
    proxies: Vec<JsonProxy>,
    recommended: Option<String>,
    /// The proxy requires per-host credentials (the URLs above carry none).
    proxy_auth: bool,
}

/// Proxy addresses from the manager's hints; the CA files are refreshed on the way.
/// `recommended` is the first hint that accepts a TCP connection.
pub(crate) struct Resolved {
    info: ProxyInfo,
    proxies: Vec<JsonProxy>,
    recommended: Option<usize>,
}

impl Resolved {
    /// The recommended proxy as (hint, port): the first hint accepting TCP.
    pub(crate) fn recommended(&self) -> Result<(&str, u16), CliError> {
        let i = self.recommended.ok_or_else(|| unreachable_error(self.info.port))?;
        Ok((&self.info.hints[i], self.info.port))
    }

    /// The proxy requires per-host credentials ([`proxy_authorization`]).
    pub(crate) fn proxy_auth(&self) -> bool {
        self.info.proxy_auth
    }
}

fn resolve() -> Result<(HostState, Resolved), CliError> {
    let s = Session::open()?;
    s.warn_secrets();
    s.sync_leases()?;
    Ok((s.host, resolve_for(&s.api)?))
}

/// Resolve proxy/CA metadata without opening a secrets directory or starting a reaper.
pub(crate) fn resolve_for(api: &Api) -> Result<Resolved, CliError> {
    let info: ProxyInfo = api.get("/proxy-info")?;
    refresh_ca(api, &info)?;
    let mut recommended = None;
    let proxies = info
        .hints
        .iter()
        .enumerate()
        .map(|(i, h)| {
            // Probe until one answers; later hints are listed but not probed.
            let recommend = recommended.is_none() && accepts_tcp(h, info.port);
            if recommend {
                recommended = Some(i);
            }
            JsonProxy {
                hint: h.clone(),
                http: format!("http://{}", authority(h, info.port)),
                socks5h: format!("socks5h://{}", authority(h, info.port)),
                recommended: recommend,
            }
        })
        .collect();
    Ok(Resolved {
        info,
        proxies,
        recommended,
    })
}

pub(crate) fn environment(host: &HostState, api: &Api) -> Result<Vec<(&'static str, String)>, CliError> {
    let r = resolve_for(api)?;
    let i = r.recommended.ok_or_else(|| unreachable_error(r.info.port))?;
    exports(host, &r, i)
}

fn unreachable_error(port: u16) -> CliError {
    CliError::failure(format!(
        "no proxy hint accepts TCP connections on port {port}; check the network path to the manager's Mac"
    ))
}

/// `asm proxy-info`: what the proxy is and how to reach it. Informational only; use
/// `asm proxy-env` for shell variables.
pub fn proxy_info(json: bool) -> Result<(), CliError> {
    let (_, r) = resolve()?;
    let ca = state::ca_path()?.to_string_lossy().into_owned();
    let bundle = state::ca_bundle_path()?.to_string_lossy().into_owned();
    if json {
        let j = JsonProxyInfo {
            port: r.info.port,
            ca_sha256: r.info.ca_sha256.clone(),
            ca_file: ca,
            ca_bundle_file: bundle,
            recommended: r.recommended.map(|i| r.proxies[i].http.clone()),
            proxy_auth: r.info.proxy_auth,
            proxies: r.proxies,
        };
        println!("{}", serde_json::to_string_pretty(&j).expect("serializes"));
    } else {
        println!("proxy port: {}", r.info.port);
        for p in &r.proxies {
            let mark = if p.recommended { "  (recommended)" } else { "" };
            println!("  {}{mark}", p.http);
            println!("  {}{mark}", p.socks5h);
        }
        if r.proxies.is_empty() {
            println!("  (the manager lists no hostname hints)");
        }
        println!("CA certificate: {ca}");
        println!("CA bundle (system roots + proxy CA): {bundle}");
        println!("CA SHA-256: {}", r.info.ca_sha256);
        if r.info.proxy_auth {
            println!("auth: per-host credentials (added by asm exec, asm proxy-env and the proxy router)");
        }
        if r.recommended.is_some() {
            println!("to use it in this shell: eval \"$(asm proxy-env)\"");
        }
    }
    match r.recommended {
        Some(_) => Ok(()),
        None => Err(unreachable_error(r.info.port)),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum Shell {
    /// bash, zsh, sh: `export K='v'`
    Posix,
    /// fish: `set -gx K 'v'`
    Fish,
}

/// Names `proxy-env` sets, in output order.
pub(crate) const ENV_NAMES: [&str; 9] = [
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "NODE_EXTRA_CA_CERTS",
];

/// `asm proxy-env`: shell code only, for `eval "$(asm proxy-env)"`. Messages go to
/// stderr; when no proxy is reachable stdout stays empty and the exit code is 1.
pub fn proxy_env(shell: Shell, unset: bool) -> Result<(), CliError> {
    if unset {
        for k in ENV_NAMES {
            match shell {
                Shell::Posix => println!("unset {k}"),
                Shell::Fish => println!("set -e {k}"),
            }
        }
        return Ok(());
    }
    let (host, r) = resolve()?;
    let Some(i) = r.recommended else {
        return Err(unreachable_error(r.info.port));
    };
    for (k, v) in exports(&host, &r, i)? {
        match shell {
            Shell::Posix => println!("export {k}={}", shell_quote(&v)),
            Shell::Fish => println!("set -gx {k} {}", fish_quote(&v)),
        }
    }
    Ok(())
}

/// Single-quote for fish (escapes `\` and `'`).
fn fish_quote(s: &str) -> String {
    format!("'{}'", s.replace('\\', r"\\").replace('\'', r"\'"))
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

#[derive(Debug, PartialEq, Eq)]
enum Level {
    Ok,
    Warn,
    Fail,
}

/// Grades clock offset between this machine and the manager from the
/// manager's `Date` header. `sent` is the local time the request was sent and
/// `rtt` the time until the response arrived.
fn clock_skew(date: Option<&str>, sent: SystemTime, rtt: Duration) -> (Level, String) {
    if rtt > Duration::from_secs(2) {
        return (
            Level::Warn,
            format!(
                "round trip took {:.1}s; clock skew not measured",
                rtt.as_secs_f64()
            ),
        );
    }
    let Some(d) = date.and_then(parse_imf_fixdate) else {
        return (
            Level::Warn,
            "the manager sent no usable Date header; clock skew not checked".into(),
        );
    };
    let t0 = match sent.duration_since(UNIX_EPOCH) {
        Ok(since) => since.as_secs_f64(),
        Err(e) => -e.duration().as_secs_f64(),
    };
    let t1 = t0 + rtt.as_secs_f64();
    let d = d as f64;
    // Manager time lies in [d, d+1) while the request was in flight [t0, t1],
    // so the offset (manager minus host) lies in [lo, hi].
    let lo = d - t1;
    let hi = d + 1.0 - t0;
    let estimate = (lo + hi) / 2.0;
    let graded = if lo <= 0.0 && hi >= 0.0 {
        0.0
    } else {
        lo.abs().min(hi.abs())
    };
    let n = estimate.abs().round() as u64;
    if graded <= 5.0 {
        return (Level::Ok, format!("within {n}s of the manager"));
    }
    let direction = if estimate < 0.0 { "ahead of" } else { "behind" };
    let amount = fmt_skew(n);
    if graded <= 60.0 {
        (
            Level::Warn,
            format!(
                "this machine is {amount} {direction} the manager; generated-token renewal checks can fail near expiry. Enable time sync on both machines (Linux: timedatectl set-ntp true)"
            ),
        )
    } else {
        (
            Level::Fail,
            format!(
                "this machine is {amount} {direction} the manager; lease and token expiry checks are unreliable. Fix time sync here or on the manager's Mac"
            ),
        )
    }
}

/// `42s`, `14m`, `2h 5m`.
fn fmt_skew(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h {}m", secs / 3600, secs % 3600 / 60)
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(m);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parses an RFC 9110 IMF-fixdate (`Mon, 23 Nov 2026 22:11:17 GMT`) to Unix
/// seconds. Any other format is rejected.
fn parse_imf_fixdate(s: &str) -> Option<i64> {
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    if s.len() != 29 || !s.is_ascii() {
        return None;
    }
    let b = s.as_bytes();
    let num = |range: std::ops::Range<usize>| -> Option<u32> {
        let part = &s[range];
        if !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    if !DAYS.contains(&&s[0..3])
        || &s[3..5] != ", "
        || b[7] != b' '
        || b[11] != b' '
        || b[16] != b' '
        || b[19] != b':'
        || b[22] != b':'
        || &s[25..29] != " GMT"
    {
        return None;
    }
    let day = num(5..7)?;
    let month = MONTHS.iter().position(|m| *m == &s[8..11])? as u32 + 1;
    let year = num(12..16)?;
    let (hour, min, sec) = (num(17..19)?, num(20..22)?, num(23..25)?);
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day == 0 || day > month_days || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let days = days_from_civil(i64::from(year), month, day);
    Some(days * 86_400 + i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec))
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
            let sent = SystemTime::now();
            let started = Instant::now();
            match unauth.as_ref().map(|a| a.try_get("/health")) {
                Ok(Ok(resp)) => {
                    let rtt = started.elapsed();
                    let date = resp
                        .headers()
                        .get(reqwest::header::DATE)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    match resp.json::<HealthResponse>() {
                        Ok(hr) if hr.name == MANAGER_NAME => {
                            r.ok(
                                "manager",
                                format!(
                                    "{} reachable, certificate matches the pin (version {})",
                                    api.base(),
                                    hr.version
                                ),
                            );
                            match clock_skew(date.as_deref(), sent, rtt) {
                                (Level::Ok, msg) => r.ok("clock", msg),
                                (Level::Warn, msg) => r.warn("clock", msg),
                                (Level::Fail, msg) => r.fail("clock", msg),
                            }
                            true
                        }
                        _ => {
                            r.fail(
                                "manager",
                                format!("{} does not answer like an asm manager", api.base()),
                            );
                            false
                        }
                    }
                }
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
        browser_checks(&mut r, None);
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

    // 7. the manager's macOS Firewall (older managers do not report it: skipped)
    if let Some(blocks) = info.as_ref().and_then(|i| i.firewall_blocks_proxy) {
        if blocks {
            r.fail(
                "firewall",
                "macOS Firewall on the manager's Mac blocks iron-proxy; allow incoming connections for it (see the asm app)",
            );
        } else {
            r.ok(
                "firewall",
                "the manager's macOS Firewall does not block iron-proxy",
            );
        }
    }

    // 8. HTTPS probe through the recommended proxy, verified against ca.crt
    if let (Some(proxy), true) = (&recommended, ca_ok) {
        let creds = match (&host, &info) {
            (Some(h), Some(i)) if i.proxy_auth => Some((h.host_id.clone(), proxy_password(h))),
            _ => None,
        };
        match std::fs::read(&ca_path)
            .map_err(|e| e.to_string())
            .and_then(|pem| proxy_probe_client(proxy, &pem, creds.as_ref().map(|(u, p)| (u.as_str(), p.as_str()))))
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
                Err(e) => {
                    let chain = error_chain(&e);
                    // TCP reached the proxy (it was recommended), yet the tunnel died.
                    let hint = if looks_aborted(&chain) {
                        " (the manager's firewall may be blocking iron-proxy)"
                    } else {
                        ""
                    };
                    r.warn(
                        "probe",
                        format!("{probe_url} through {proxy}: {chain}{hint}"),
                    )
                }
            },
            Err(e) => r.fail("probe", e),
        }
    }
    browser_checks(&mut r, info.as_ref());
    finish(r)
}

/// The proxy router and the installed browsers (only when `asm browser install` ran).
fn browser_checks(r: &mut Report, info: Option<&ProxyInfo>) {
    for (level, check, detail) in crate::browser::doctor_checks(info) {
        match level {
            crate::browser::Level::Ok => r.ok(check, detail),
            crate::browser::Level::Warn => r.warn(check, detail),
            crate::browser::Level::Fail => r.fail(check, detail),
        }
    }
}

/// A connection that was accepted and then cut: CONNECT aborted, unexpected EOF, reset.
/// What a client sees when the macOS Firewall blocks the proxy (TCP still connects).
fn looks_aborted(chain: &str) -> bool {
    let c = chain.to_ascii_lowercase();
    [
        "unexpected end of file",
        "unexpected eof",
        "connection reset",
        "reset by peer",
        "connection aborted",
        "broken pipe",
        "io error establishing tunnel",
    ]
    .iter()
    .any(|m| c.contains(m))
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
    fn proxy_credentials_format() {
        let host = HostState {
            manager_url: "https://mac.ts.net:7411".into(),
            cert_sha256: String::new(),
            host_id: "h 1".into(),
            token: "tok".into(),
            paired_at: String::new(),
        };
        let password = asm_proto::crypto::proxy_password(&asm_proto::crypto::sha256(b"tok"));
        assert_eq!(proxy_password(&host), password);
        assert_eq!(password.len(), 64);
        assert_eq!(
            proxy_url("http", &host, "mac.ts.net:7412", true),
            format!("http://h%201:{password}@mac.ts.net:7412")
        );
        assert_eq!(
            proxy_url("socks5h", &host, "[fd00::1]:7412", true),
            format!("socks5h://h%201:{password}@[fd00::1]:7412")
        );
        assert_eq!(proxy_url("http", &host, "mac.ts.net:7412", false), "http://mac.ts.net:7412");
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(proxy_authorization(&host).strip_prefix("Basic ").unwrap())
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), format!("h 1:{password}"));
    }

    #[test]
    fn quoting_and_authority() {
        assert_eq!(shell_quote("http://h:7412"), "'http://h:7412'");
        assert_eq!(shell_quote("a'b"), r"'a'\''b'");
        assert_eq!(authority("fd00::1", 7412), "[fd00::1]:7412");
        assert_eq!(authority("mac.ts.net", 7412), "mac.ts.net:7412");
    }

    #[test]
    fn aborted_tunnels_are_recognised() {
        assert!(looks_aborted(
            "error sending request for url (https://example.com/): client error (Connect): tunnel error: unexpected end of file"
        ));
        assert!(looks_aborted(
            "client error (Connect): tunnel error: io error establishing tunnel: Connection reset by peer (os error 54)"
        ));
        assert!(!looks_aborted(
            "client error (Connect): dns error: failed to lookup address information"
        ));
        assert!(!looks_aborted("operation timed out"));
    }

    #[test]
    fn imf_fixdate_parsing() {
        assert_eq!(parse_imf_fixdate("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2026, 11, 23), 20_780);
        assert_eq!(
            parse_imf_fixdate("Mon, 23 Nov 2026 22:11:17 GMT"),
            Some(20_780 * 86_400 + 22 * 3600 + 11 * 60 + 17)
        );
        assert_eq!(parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
        assert_eq!(parse_imf_fixdate("Thu, 29 Feb 2024 00:00:00 GMT"), Some(1_709_164_800));
        for bad in [
            "",
            "Mon, 23 Nov 2026 22:11:17 UTC",
            "Mon, 23 Foo 2026 22:11:17 GMT",
            "Mon, 32 Nov 2026 22:11:17 GMT",
            "Thu, 29 Feb 2023 00:00:00 GMT",
            "Mon, 23 Nov 2026 24:00:00 GMT",
            "Mon, 23 Nov 2026 22:61:17 GMT",
            "Xyz, 23 Nov 2026 22:11:17 GMT",
            "Mon, 23 Nov 2026 22:11:17 GMT ",
            "Monday, 23-Nov-26 22:11:17 GMT",
            "Mon, +3 Nov 2026 22:11:17 GMT",
        ] {
            assert_eq!(parse_imf_fixdate(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn clock_skew_grading() {
        let at = |secs: u64| UNIX_EPOCH + Duration::from_secs(secs);
        let date = |t: i64| {
            // IMF-fixdate for 2026-11-23 00:00:00 GMT + t.
            assert!((0..86_400).contains(&t));
            let s = format!(
                "Mon, 23 Nov 2026 {:02}:{:02}:{:02} GMT",
                t / 3600,
                t % 3600 / 60,
                t % 60
            );
            assert_eq!(
                parse_imf_fixdate(&s),
                Some(days_from_civil(2026, 11, 23) * 86_400 + t)
            );
            s
        };
        let base = days_from_civil(2026, 11, 23) as u64 * 86_400;
        let rtt = Duration::from_millis(100);
        let noon = 12 * 3600;

        let (level, msg) = clock_skew(Some(&date(noon)), at(base + noon as u64), rtt);
        assert_eq!(level, Level::Ok);
        assert_eq!(msg, "within 0s of the manager");

        let (level, msg) = clock_skew(Some(&date(noon + 30)), at(base + noon as u64), rtt);
        assert_eq!(level, Level::Warn);
        assert!(msg.starts_with("this machine is 30s behind the manager;"), "{msg}");

        let (level, msg) = clock_skew(Some(&date(noon - 30)), at(base + noon as u64), rtt);
        assert_eq!(level, Level::Warn);
        assert!(msg.starts_with("this machine is 30s ahead of the manager;"), "{msg}");

        let (level, msg) = clock_skew(Some(&date(noon + 600)), at(base + noon as u64), rtt);
        assert_eq!(level, Level::Fail);
        assert!(msg.starts_with("this machine is 10m behind the manager;"), "{msg}");

        let (level, msg) = clock_skew(
            Some(&date(noon)),
            at(base + noon as u64),
            Duration::from_millis(2500),
        );
        assert_eq!(level, Level::Warn);
        assert_eq!(msg, "round trip took 2.5s; clock skew not measured");

        let (level, msg) = clock_skew(None, at(base + noon as u64), rtt);
        assert_eq!(level, Level::Warn);
        assert_eq!(msg, "the manager sent no usable Date header; clock skew not checked");
        let (level, _) = clock_skew(Some("garbage"), at(base + noon as u64), rtt);
        assert_eq!(level, Level::Warn);

        assert_eq!(fmt_skew(42), "42s");
        assert_eq!(fmt_skew(14 * 60 + 5), "14m");
        assert_eq!(fmt_skew(2 * 3600 + 5 * 60), "2h 5m");
    }
}
