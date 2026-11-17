//! Activity events from the proxy: iron-proxy's JSON request lines that carried a
//! substitution or were rejected by the secrets transform, plus supervisor lifecycle
//! events. Parsed from the already redacted log line on the log thread; mapped to leases
//! by the activity writer.

use serde_json::Value;

/// Sent from the proxy's threads to the manager (never blocks on SQLite).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyEvent {
    Request(AuditLine),
    /// `kind`: `started`, `restarted`, `crashed`, `start_failed`, `reload_failed`, `down`,
    /// `unhealthy`, `recovered`, `orphan_killed`.
    Lifecycle {
        kind: &'static str,
        summary: String,
    },
}

/// One substituted secret: the value file the config points at and where it was found
/// (`header:X-Key`, `query:q`, `path`, `body`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Swap {
    pub value_path: String,
    pub locations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reject {
    /// e.g. `sentinel_not_valid`, `sentinel_ended`, `websocket_upgrade`,
    /// `content_encoded_response`.
    pub reason: Option<String>,
    /// Value file of the entry whose sentinel was refused, when known (never for
    /// `sentinel_ended`: ended entries have no value file).
    pub value_path: Option<String>,
}

/// The parts of a request line the activity log keeps. `path` has no query string.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuditLine {
    pub method: String,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    pub remote_addr: String,
    pub swaps: Vec<Swap>,
    pub rejected: Option<Reject>,
}

fn str_of(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Parse a (redacted) iron-proxy log line. `None` unless it is a request line that
/// substituted a secret or was rejected by the secrets transform.
pub fn parse(line: &str) -> Option<AuditLine> {
    if !line.contains("\"swapped\"") && !line.contains("\"rejected_by\"") {
        return None;
    }
    let v: Value = serde_json::from_str(line).ok()?;
    if v.get("msg").and_then(Value::as_str) != Some("request") {
        return None;
    }
    let audit = v.get("audit")?;
    let rejected_by_secrets = v.get("rejected_by").and_then(Value::as_str) == Some("secrets");

    let mut swaps = Vec::new();
    let mut rejected: Option<Reject> = None;
    for phase in ["request_transforms", "response_transforms"] {
        let Some(list) = v.get(phase).and_then(Value::as_array) else {
            continue;
        };
        for t in list
            .iter()
            .filter(|t| t.get("name").and_then(Value::as_str) == Some("secrets"))
        {
            let Some(ann) = t.get("annotations") else {
                continue;
            };
            for s in ann
                .get("swapped")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                swaps.push(Swap {
                    value_path: str_of(s, "secret"),
                    locations: s
                        .get("locations")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect(),
                });
            }
            let reason = ann.get("reject_reason").and_then(Value::as_str);
            let value_path = ann.get("rejected").and_then(Value::as_str);
            if rejected_by_secrets && (reason.is_some() || value_path.is_some()) {
                rejected = Some(Reject {
                    reason: reason.map(str::to_string),
                    value_path: value_path.map(str::to_string),
                });
            }
        }
    }
    if rejected_by_secrets && rejected.is_none() {
        rejected = Some(Reject {
            reason: None,
            value_path: None,
        });
    }
    if swaps.is_empty() && rejected.is_none() {
        return None;
    }
    let path = str_of(audit, "path");
    let path = path
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .to_string();
    Some(AuditLine {
        method: str_of(audit, "method"),
        host: str_of(audit, "host"),
        path,
        status: audit
            .get("status_code")
            .and_then(Value::as_u64)
            .and_then(|s| u16::try_from(s).ok()),
        remote_addr: str_of(audit, "remote_addr"),
        swaps,
        rejected,
    })
}

/// `<values>/<lease_id>.<n>` → `(lease_id, n)`. `None` for other files.
pub fn lease_of_value_path(path: &str) -> Option<(String, usize)> {
    let name = std::path::Path::new(path).file_name()?.to_str()?;
    let (id, n) = name.rsplit_once('.')?;
    let n: usize = n.parse().ok()?;
    (!id.is_empty()).then(|| (id.to_string(), n))
}

/// Operator-facing text for a `reject_reason` code.
pub fn reject_text(reason: &str) -> &str {
    match reason {
        "sentinel_not_valid" => "sentinel not valid for this host or scheme",
        "sentinel_ended" => "lease expired or revoked",
        "secret_unavailable" => "secret unavailable",
        "websocket_upgrade" => "sentinels are not substituted on WebSocket upgrades",
        "content_encoded_response" => "upstream response is content-encoded",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SWAP: &str = r#"{"time":"2026-11-16T16:50:34.281492+11:00","level":"INFO","msg":"request","audit":{"host":"httpbingo.org","method":"GET","path":"/headers?x=1","remote_addr":"127.0.0.1:57217","sni":"httpbingo.org","mode":"mitm","action":"allow","status_code":200,"duration_ms":412.266},"tunnel":{"target":"httpbingo.org:443","request_transforms":[{"name":"secrets","action":"allow","duration_ms":0.003}]},"request_transforms":[{"name":"secrets","action":"allow","duration_ms":0.506,"annotations":{"swapped":[{"secret":"/tmp/net.thinkscape.asm/values/7637e5fd-7d0d-491b-93e6-45096c02e94c.0","locations":["header:X-Key"]}]}}],"response_transforms":[{"name":"secrets","action":"allow","duration_ms":0.118}]}"#;
    const REJECT: &str = r#"{"time":"2026-11-16T16:50:50.845653+11:00","level":"WARN","msg":"request","audit":{"host":"httpbingo.org","method":"GET","path":"/headers","remote_addr":"127.0.0.1:57291","sni":"httpbingo.org","mode":"mitm","action":"reject","status_code":403,"duration_ms":0.023},"tunnel":{"target":"httpbingo.org:443","request_transforms":[{"name":"secrets","action":"allow","duration_ms":0.003}]},"rejected_by":"secrets","request_transforms":[{"name":"secrets","action":"reject","duration_ms":0.017,"annotations":{"reject_reason":"sentinel_not_valid","rejected":"/tmp/net.thinkscape.asm/values/7637e5fd-7d0d-491b-93e6-45096c02e94c.0"}}]}"#;
    const ENDED: &str = r#"{"time":"2026-11-17T09:12:03.5+11:00","level":"WARN","msg":"request","audit":{"host":"httpbingo.org","method":"GET","path":"/headers","remote_addr":"127.0.0.1:57301","sni":"httpbingo.org","mode":"mitm","action":"reject","status_code":403,"duration_ms":0.019},"rejected_by":"secrets","request_transforms":[{"name":"secrets","action":"reject","duration_ms":0.011,"annotations":{"reject_reason":"sentinel_ended"}}]}"#;
    const PLAIN: &str = r#"{"time":"2026-11-16T16:50:34Z","level":"INFO","msg":"request","audit":{"host":"example.com","method":"GET","path":"/","status_code":200},"request_transforms":[{"name":"secrets","action":"allow"}]}"#;

    #[test]
    fn parses_a_substitution_line() {
        let a = parse(SWAP).expect("swap line");
        assert_eq!(a.method, "GET");
        assert_eq!(a.host, "httpbingo.org");
        assert_eq!(a.path, "/headers", "query string stripped");
        assert_eq!(a.status, Some(200));
        assert_eq!(a.swaps.len(), 1);
        assert_eq!(a.swaps[0].locations, ["header:X-Key"]);
        assert_eq!(
            lease_of_value_path(&a.swaps[0].value_path),
            Some(("7637e5fd-7d0d-491b-93e6-45096c02e94c".to_string(), 0))
        );
        assert!(a.rejected.is_none());
    }

    #[test]
    fn parses_a_rejected_line() {
        let a = parse(REJECT).expect("reject line");
        assert_eq!(a.status, Some(403));
        let r = a.rejected.unwrap();
        assert_eq!(r.reason.as_deref(), Some("sentinel_not_valid"));
        assert_eq!(
            lease_of_value_path(r.value_path.as_deref().unwrap()),
            Some(("7637e5fd-7d0d-491b-93e6-45096c02e94c".to_string(), 0))
        );
    }

    #[test]
    fn parses_an_ended_sentinel_line() {
        let a = parse(ENDED).expect("ended line");
        assert_eq!(a.status, Some(403));
        let r = a.rejected.unwrap();
        assert_eq!(r.reason.as_deref(), Some("sentinel_ended"));
        assert_eq!(r.value_path, None);
        assert_eq!(reject_text("sentinel_ended"), "lease expired or revoked");
    }

    #[test]
    fn ignores_ordinary_lines() {
        assert!(parse(PLAIN).is_none());
        assert!(parse("asm: started iron-proxy pid 1").is_none());
        assert!(parse(r#"{"msg":"iron-proxy starting","swapped":1}"#).is_none());
    }
}
