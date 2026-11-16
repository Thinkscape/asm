//! Manager API client (`/v1/...`) over pinned TLS.

use crate::error::CliError;
use crate::state::HostState;
use crate::tls::{Pin, error_chain, is_tls_error, manager_client};
use asm_proto::error::ApiError;
use asm_proto::wire::DEFAULT_API_PORT;
use reqwest::blocking::{Client, RequestBuilder};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::time::Duration;

/// Generous enough for the manager's 25 s long polls.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

pub struct Api {
    client: Client,
    base: String,
    token: Option<String>,
}

/// Turn `<hostname>[:port]` (IPv6 as `[addr]:port` or bare) into `https://host:port`.
pub fn manager_url(target: &str) -> Result<String, CliError> {
    let t = target.trim().trim_end_matches('/');
    let t = t.strip_prefix("https://").unwrap_or(t);
    let bad = || {
        CliError::invalid(format!(
            "manager address {target:?} must be <hostname>[:port]"
        ))
    };
    let (host, port) = if let Some(rest) = t.strip_prefix('[') {
        let (h, after) = rest.split_once(']').ok_or_else(bad)?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or_else(bad)?),
        };
        (h, port)
    } else if t.matches(':').count() > 1 {
        (t, None)
    } else if let Some((h, p)) = t.split_once(':') {
        (h, Some(p))
    } else {
        (t, None)
    };
    if host.is_empty() || host.contains(['/', '@', ' ', '?', '#']) {
        return Err(bad());
    }
    let port = match port {
        None => DEFAULT_API_PORT,
        Some(p) => p.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(bad)?,
    };
    Ok(if host.contains(':') {
        format!("https://[{host}]:{port}")
    } else {
        format!("https://{host}:{port}")
    })
}

impl Api {
    pub fn new(base: String, pin: Pin, token: Option<String>) -> Result<Self, CliError> {
        let client = manager_client(pin, REQUEST_TIMEOUT).map_err(CliError::failure)?;
        Ok(Api {
            client,
            base,
            token,
        })
    }

    /// Client for a paired host: pinned certificate, bearer token.
    pub fn for_host(state: &HostState) -> Result<Self, CliError> {
        Self::new(
            state.manager_url.clone(),
            Pin::Fixed(state.pin()?),
            Some(state.token.clone()),
        )
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1{path}", self.base)
    }

    fn send(&self, rb: RequestBuilder) -> Result<Vec<u8>, CliError> {
        let rb = match &self.token {
            Some(t) => rb.bearer_auth(t),
            None => rb,
        };
        let resp = rb.send().map_err(|e| self.transport_error(&e))?;
        let status = resp.status();
        let body = resp.bytes().map_err(|e| self.transport_error(&e))?.to_vec();
        if status.is_success() {
            return Ok(body);
        }
        match ApiError::from_json(&body) {
            Some(e) => Err(e.into()),
            None => Err(CliError::failure(format!("manager answered HTTP {status}"))),
        }
    }

    fn transport_error(&self, e: &reqwest::Error) -> CliError {
        if is_tls_error(e) {
            CliError::failure(format!(
                "TLS error talking to the manager at {}: {}",
                self.base,
                error_chain(e)
            ))
        } else {
            CliError::failure(format!(
                "cannot reach the manager at {}: {}",
                self.base,
                error_chain(e)
            ))
        }
    }

    fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, CliError> {
        serde_json::from_slice(body)
            .map_err(|e| CliError::failure(format!("unexpected answer from the manager: {e}")))
    }

    /// GET returning the raw body.
    pub fn get_bytes(&self, path: &str) -> Result<Vec<u8>, CliError> {
        self.send(self.client.get(self.url(path)))
    }

    pub fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, CliError> {
        Self::decode(&self.get_bytes(path)?)
    }

    pub fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        Self::decode(&self.send(self.client.post(self.url(path)).json(body))?)
    }

    /// Raw `reqwest` result of `GET path`, for checks that classify transport errors.
    pub fn try_get(&self, path: &str) -> Result<reqwest::blocking::Response, reqwest::Error> {
        let rb = self.client.get(self.url(path));
        match &self.token {
            Some(t) => rb.bearer_auth(t),
            None => rb,
        }
        .send()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_urls() {
        assert_eq!(manager_url("mac.local").unwrap(), "https://mac.local:7411");
        assert_eq!(
            manager_url("mac.local:8000").unwrap(),
            "https://mac.local:8000"
        );
        assert_eq!(manager_url("10.0.0.2").unwrap(), "https://10.0.0.2:7411");
        assert_eq!(
            manager_url("[fd00::1]:7411").unwrap(),
            "https://[fd00::1]:7411"
        );
        assert_eq!(manager_url("fd00::1").unwrap(), "https://[fd00::1]:7411");
        assert_eq!(
            manager_url("https://mac.local:7411/").unwrap(),
            "https://mac.local:7411"
        );
        assert!(manager_url("").is_err());
        assert!(manager_url("mac:abc").is_err());
        assert!(manager_url("mac:0").is_err());
        assert!(manager_url("a/b").is_err());
    }
}
