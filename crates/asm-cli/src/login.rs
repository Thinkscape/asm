//! Operator-assisted browser sign-in and browser login site discovery.

use crate::api::Api;
use crate::error::CliError;
use crate::requests::{Session, deadline, submit, unix_now};
use asm_proto::wire::{
    BrowserLoginMode, BrowserLoginRequest, CAPABILITY_BROWSER_LOGIN_V2, GetResult, HealthResponse,
    LeaseMode, LoginSitesResponse, RequestBody, RequestResult,
};
use serde::Serialize;
use std::path::PathBuf;

/// The one file of a broker result.
const STORAGE_STATE: &str = "storage-state";
/// Most `--fill-origin` values.
const MAX_FILL_ORIGINS: usize = 5;

#[derive(clap::Args)]
pub struct LoginArgs {
    /// HTTPS page to sign in on; cookies for its host and its origin's localStorage are
    /// handed over.
    pub url: String,
    /// Recognize the removed positional ITEM only to give migration guidance.
    #[arg(hide = true)]
    pub legacy_item: Option<String>,
    /// Requested username or email; the operator chooses the login.
    #[arg(long, value_name = "USERNAME_OR_EMAIL")]
    pub account: Option<String>,
    /// Why you need to sign in (shown to the operator; required).
    #[arg(long, value_name = "TEXT")]
    pub reason: Option<String>,
    /// Another origin the sign-in passes through: the vault login may be filled there and
    /// its host's cookies are handed over too. Pass the sign-in service's origin when it
    /// differs from the site (Clerk, Auth0: https://clerk.example.com). https://host[:port];
    /// repeatable, at most 5.
    #[arg(long = "fill-origin", value_name = "ORIGIN")]
    pub fill_origins: Vec<String>,
    /// Stop waiting for the operator after this many seconds (exit 4 while still pending).
    #[arg(long, default_value_t = 900)]
    pub wait: u64,
    #[arg(long)]
    pub json: bool,
}

pub(crate) fn no_positional_item() -> CliError {
    CliError::invalid(
        "browser sign-in no longer accepts a positional ITEM; omit it and optionally pass --account USERNAME_OR_EMAIL (the operator chooses the login)",
    )
}

pub(crate) fn require_v2(api: &Api) -> Result<(), CliError> {
    let health: HealthResponse = api.get("/health")?;
    health.require_capability(CAPABILITY_BROWSER_LOGIN_V2).map_err(CliError::from)
}

pub(crate) fn submit_browser(
    api: &Api,
    body: &RequestBody,
    wait: Option<u64>,
) -> Result<GetResult, CliError> {
    let (result, _) = submit(api, body, deadline(wait)).map_err(|e| {
        if e.message == CliError::acquisition_elapsed().message { CliError::pending() } else { e }
    })?;
    let RequestResult::Get(result) = result else {
        return Err(CliError::failure("the manager sent an unexpected result for a browser sign-in"));
    };
    Ok(result)
}

pub(crate) fn list_sites(json: bool) -> Result<(), CliError> {
    let s = Session::open()?;
    s.warn_secrets();
    require_v2(&s.api)?;
    s.sync_leases()?;
    let response: LoginSitesResponse = s.api.get("/login-sites")?;
    if json {
        println!("{}", serde_json::to_string(&response).expect("serializes"));
    } else {
        for site in response.sites {
            println!("{site}");
        }
    }
    Ok(())
}

/// `https://host[:port]` (`:443` omitted) for an origin with nothing after the authority.
fn fill_origin(s: &str) -> Result<String, CliError> {
    let shape = || CliError::invalid(format!("--fill-origin {s:?} must be https://host[:port]"));
    let after = s.get(8..).filter(|_| s[..8].eq_ignore_ascii_case("https://")).ok_or_else(shape)?;
    if after.contains(['/', '?', '#']) {
        return Err(shape());
    }
    let (host, port) = asm_proto::rules::parse_https_url(s)
        .map_err(|e| CliError::invalid(format!("--fill-origin {s:?}: {}", e.message)))?;
    Ok(match port {
        443 => format!("https://{host}"),
        p => format!("https://{host}:{p}"),
    })
}

fn fill_origins(values: &[String]) -> Result<Vec<String>, CliError> {
    let mut out: Vec<String> = Vec::new();
    for v in values {
        let o = fill_origin(v)?;
        if !out.contains(&o) {
            out.push(o);
        }
    }
    if out.len() > MAX_FILL_ORIGINS {
        return Err(CliError::invalid(format!("at most {MAX_FILL_ORIGINS} --fill-origin values")));
    }
    Ok(out)
}

/// The cookie domains of a Playwright storage state, in order, without repeats.
fn cookie_domains(state: &str) -> Option<Vec<String>> {
    let v: serde_json::Value = serde_json::from_str(state).ok()?;
    let cookies = v.get("cookies")?.as_array()?;
    if !v.get("origins").is_none_or(serde_json::Value::is_array) {
        return None;
    }
    let mut out: Vec<String> = Vec::new();
    for c in cookies {
        let d = c.get("domain")?.as_str()?;
        if !out.iter().any(|x| x == d) {
            out.push(d.to_owned());
        }
    }
    Some(out)
}

/// Only a raw lease with one `storage-state` file holding a storage state is accepted.
/// Returns its cookie domains.
fn check_result(r: &GetResult) -> Result<Vec<String>, CliError> {
    let wrong = || {
        CliError::failure("the manager did not return a browser storage state (expected one raw storage-state file)")
    };
    let [file] = r.files.as_slice() else {
        return Err(wrong());
    };
    if !asm_proto::crypto::is_uuid(&r.lease_id)
        || r.mode != LeaseMode::Raw
        || !r.hosts.is_empty()
        || r.generation.is_some()
        || r.login.is_some()
        || r.validate().is_err()
        || file.field != STORAGE_STATE
        || file.substituted != Some(false)
        || r.expires_at.as_deref().and_then(asm_proto::time::parse_unix).is_none_or(|t| t <= unix_now())
    {
        return Err(wrong());
    }
    cookie_domains(&file.content).ok_or_else(|| CliError::failure("the manager sent an invalid storage state"))
}

#[derive(Serialize)]
struct JsonLogin<'a> {
    lease_id: &'a str,
    expires_at: &'a Option<String>,
    path: &'a PathBuf,
    cookie_domains: &'a [String],
}

pub fn run(a: LoginArgs) -> Result<(), CliError> {
    if a.legacy_item.is_some() {
        return Err(no_positional_item());
    }
    let reason = a.reason.ok_or_else(|| CliError::invalid("asm login needs --reason TEXT"))?;
    let reason = asm_proto::rules::validate_reason(&reason)?;
    asm_proto::rules::parse_https_url(&a.url)?;
    let extra_fill_origins = fill_origins(&a.fill_origins)?;
    let mut body = RequestBody::BrowserLogin(BrowserLoginRequest {
        mode: BrowserLoginMode::Broker,
        url: a.url,
        site: None,
        account: a.account,
        reason,
        extra_fill_origins,
        agent: crate::hostinfo::agent_label(),
        client_capabilities: vec![CAPABILITY_BROWSER_LOGIN_V2.to_owned()],
    });
    body.canonicalize()?;
    let s = Session::open()?;
    let dir = s.secrets_dir()?;
    require_v2(&s.api)?;
    s.sync_leases()?;
    let result = submit_browser(&s.api, &body, Some(a.wait))?;
    let domains = check_result(&result)?;
    let stored = dir.store(&result)?;
    crate::reaper::ensure_running(dir);
    let [file] = stored.as_slice() else {
        return Err(CliError::failure("the storage state was not written"));
    };
    file.delivery.report(&file.relative_path);
    if a.json {
        let j = JsonLogin {
            lease_id: &result.lease_id,
            expires_at: &result.expires_at,
            path: &file.path,
            cookie_domains: &domains,
        };
        println!("{}", serde_json::to_string_pretty(&j).expect("serializes"));
    } else {
        let domains = if domains.is_empty() { "none".to_owned() } else { domains.join(", ") };
        println!(
            "storage state: {}\ncookie domains: {domains}\nexpires: {}",
            file.path.display(),
            result.expires_at.as_deref().unwrap_or("never")
        );
    }
    let path = file.path.display();
    eprintln!(
        "load it with your browser tool: omp tab.loadState({path}), Playwright MCP --storage-state {path}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_origins_are_https_origins() {
        assert_eq!(fill_origin("https://Login.Example.com").unwrap(), "https://login.example.com");
        assert_eq!(fill_origin("https://sso.example.com:443").unwrap(), "https://sso.example.com");
        assert_eq!(fill_origin("https://sso.example.com:8443").unwrap(), "https://sso.example.com:8443");
        for bad in ["http://sso.example.com", "https://sso.example.com/", "https://sso.example.com/login", "https://a.b?x", "sso.example.com", "https://1.2.3.4", "https://u@a.b"] {
            assert!(fill_origin(bad).is_err(), "{bad}");
        }
        let many: Vec<String> = (0..6).map(|i| format!("https://s{i}.example.com")).collect();
        assert!(fill_origins(&many).is_err());
        let dup = vec!["https://a.example.com".to_owned(), "https://A.example.com:443".to_owned()];
        assert_eq!(fill_origins(&dup).unwrap(), vec!["https://a.example.com"]);
    }

    #[test]
    fn storage_state_domains() {
        assert_eq!(
            cookie_domains(r#"{"cookies":[{"name":"a","domain":"x.test"},{"name":"b","domain":".x.test"},{"name":"c","domain":"x.test"}],"origins":[]}"#),
            Some(vec!["x.test".to_owned(), ".x.test".to_owned()])
        );
        assert_eq!(cookie_domains(r#"{"cookies":[]}"#), Some(vec![]));
        assert_eq!(cookie_domains(r#"{"origins":[]}"#), None);
        assert_eq!(cookie_domains("not json"), None);
    }
}
