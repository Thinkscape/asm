//! Manager settings, stored as JSON values in the `settings` table.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{CoreError, Result};
use crate::proxy::ProxyConfig;
use crate::store::Store;

pub const API_BIND: &str = "api.bind";
pub const API_PORT: &str = "api.port";
pub const PROXY_BIND: &str = "proxy.bind";
pub const PROXY_PORT: &str = "proxy.port";
pub const PROXY_HTTP_PORT: &str = "proxy.http_port";
pub const PROXY_HTTPS_PORT: &str = "proxy.https_port";
pub const PROXY_MGMT_PORT: &str = "proxy.mgmt_port";
pub const PROXY_METRICS_PORT: &str = "proxy.metrics_port";
pub const PROXY_MAX_BODY: &str = "proxy.max_body";
pub const PROXY_ALLOW_PLAIN_HTTP: &str = "proxy.allow_plain_http";
pub const PROXY_REQUIRE_AUTH: &str = "proxy.require_auth";
/// Hidden (no UI): overrides the proxy's `upstream_deny_cidrs`; used by tests.
pub const PROXY_UPSTREAM_DENY_CIDRS: &str = "proxy.upstream_deny_cidrs";
pub const PROXY_HINTS: &str = "proxy.hints";
pub const LEASE_DEFAULT_SECS: &str = "lease.default_secs";
pub const REQUEST_LIFETIME_SECS: &str = "request.lifetime_secs";
pub const BW_PATH: &str = "bw.path";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub api_bind: String,
    pub api_port: u16,
    pub proxy: ProxyConfig,
    pub proxy_hints: Vec<String>,
    /// `None` = unlimited.
    pub lease_default_secs: Option<u64>,
    pub request_lifetime_secs: u64,
    /// Default `bw` binary for Bitwarden vaults without their own path.
    pub bw_path: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            api_bind: "0.0.0.0".into(),
            api_port: asm_proto::wire::DEFAULT_API_PORT,
            proxy: ProxyConfig::default(),
            proxy_hints: Vec::new(),
            lease_default_secs: Some(asm_proto::wire::DEFAULT_LEASE_SECS),
            request_lifetime_secs: 600,
            bw_path: None,
        }
    }
}

fn get<T: DeserializeOwned>(store: &Store, key: &str, default: T) -> Result<T> {
    match store.get_setting(key)? {
        None => Ok(default),
        Some(s) => {
            serde_json::from_str(&s).map_err(|e| CoreError::internal(format!("setting {key}: {e}")))
        }
    }
}

fn put<T: Serialize + ?Sized>(store: &Store, key: &str, v: &T) -> Result<()> {
    store.set_setting(key, &serde_json::to_string(v)?)
}

impl Settings {
    pub fn load(store: &Store) -> Result<Self> {
        let d = Settings::default();
        let p = d.proxy.clone();
        Ok(Self {
            api_bind: get(store, API_BIND, d.api_bind)?,
            api_port: get(store, API_PORT, d.api_port)?,
            proxy: ProxyConfig {
                bind: get(store, PROXY_BIND, p.bind)?,
                port: get(store, PROXY_PORT, p.port)?,
                http_port: get(store, PROXY_HTTP_PORT, p.http_port)?,
                https_port: get(store, PROXY_HTTPS_PORT, p.https_port)?,
                mgmt_port: get(store, PROXY_MGMT_PORT, p.mgmt_port)?,
                metrics_port: get(store, PROXY_METRICS_PORT, p.metrics_port)?,
                max_body: get(store, PROXY_MAX_BODY, p.max_body)?,
                allow_plain_http: get(store, PROXY_ALLOW_PLAIN_HTTP, p.allow_plain_http)?,
                require_auth: get(store, PROXY_REQUIRE_AUTH, p.require_auth)?,
                upstream_deny_cidrs: get(store, PROXY_UPSTREAM_DENY_CIDRS, p.upstream_deny_cidrs)?,
            },
            proxy_hints: get(store, PROXY_HINTS, d.proxy_hints)?,
            lease_default_secs: get(store, LEASE_DEFAULT_SECS, d.lease_default_secs)?,
            request_lifetime_secs: get(store, REQUEST_LIFETIME_SECS, d.request_lifetime_secs)?,
            bw_path: get(store, BW_PATH, d.bw_path)?,
        })
    }

    /// Persist every value.
    pub fn save(&self, store: &Store) -> Result<()> {
        put(store, API_BIND, &self.api_bind)?;
        put(store, API_PORT, &self.api_port)?;
        self.save_proxy(store)?;
        put(store, PROXY_HINTS, &self.proxy_hints)?;
        put(store, LEASE_DEFAULT_SECS, &self.lease_default_secs)?;
        put(store, REQUEST_LIFETIME_SECS, &self.request_lifetime_secs)?;
        put(store, BW_PATH, &self.bw_path)
    }

    pub fn save_proxy(&self, store: &Store) -> Result<()> {
        let p = &self.proxy;
        put(store, PROXY_BIND, &p.bind)?;
        put(store, PROXY_PORT, &p.port)?;
        put(store, PROXY_HTTP_PORT, &p.http_port)?;
        put(store, PROXY_HTTPS_PORT, &p.https_port)?;
        put(store, PROXY_MGMT_PORT, &p.mgmt_port)?;
        put(store, PROXY_METRICS_PORT, &p.metrics_port)?;
        put(store, PROXY_MAX_BODY, &p.max_body)?;
        put(store, PROXY_ALLOW_PLAIN_HTTP, &p.allow_plain_http)?;
        put(store, PROXY_REQUIRE_AUTH, &p.require_auth)?;
        // `upstream_deny_cidrs` is hidden: only written when explicitly set (tests).
        if p.upstream_deny_cidrs.is_some() {
            put(store, PROXY_UPSTREAM_DENY_CIDRS, &p.upstream_deny_cidrs)?;
        }
        Ok(())
    }

    /// Write raw JSON overrides (e.g. from tests) before `load`. Unknown keys are rejected.
    pub fn seed(store: &Store, overrides: &[(String, serde_json::Value)]) -> Result<()> {
        const KEYS: &[&str] = &[
            API_BIND,
            API_PORT,
            PROXY_BIND,
            PROXY_PORT,
            PROXY_HTTP_PORT,
            PROXY_HTTPS_PORT,
            PROXY_MGMT_PORT,
            PROXY_METRICS_PORT,
            PROXY_MAX_BODY,
            PROXY_ALLOW_PLAIN_HTTP,
            PROXY_REQUIRE_AUTH,
            PROXY_UPSTREAM_DENY_CIDRS,
            PROXY_HINTS,
            LEASE_DEFAULT_SECS,
            REQUEST_LIFETIME_SECS,
            BW_PATH,
        ];
        for (k, v) in overrides {
            if !KEYS.contains(&k.as_str()) {
                return Err(CoreError::invalid(format!("unknown setting {k}")));
            }
            store.set_setting(k, &v.to_string())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("asm.db")).unwrap();
        assert_eq!(Settings::load(&store).unwrap(), Settings::default());
        Settings::seed(
            &store,
            &[
                (API_PORT.into(), serde_json::json!(0)),
                (
                    PROXY_UPSTREAM_DENY_CIDRS.into(),
                    serde_json::json!(["192.0.2.0/24"]),
                ),
                (LEASE_DEFAULT_SECS.into(), serde_json::Value::Null),
            ],
        )
        .unwrap();
        let s = Settings::load(&store).unwrap();
        assert_eq!(s.api_port, 0);
        assert_eq!(
            s.proxy.upstream_deny_cidrs,
            Some(vec!["192.0.2.0/24".to_string()])
        );
        assert_eq!(s.lease_default_secs, None);
        assert!(Settings::seed(&store, &[("nope".into(), serde_json::json!(1))]).is_err());
        s.save(&store).unwrap();
        assert_eq!(Settings::load(&store).unwrap(), s);
    }

    #[test]
    fn require_auth_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("asm.db")).unwrap();
        assert!(!Settings::load(&store).unwrap().proxy.require_auth, "off by default");
        Settings::seed(&store, &[(PROXY_REQUIRE_AUTH.into(), serde_json::json!(true))]).unwrap();
        let mut s = Settings::load(&store).unwrap();
        assert!(s.proxy.require_auth);
        s.proxy.require_auth = false;
        s.save_proxy(&store).unwrap();
        assert!(!Settings::load(&store).unwrap().proxy.require_auth);
        s.proxy.require_auth = true;
        s.save(&store).unwrap();
        assert_eq!(Settings::load(&store).unwrap(), s);
    }
}
