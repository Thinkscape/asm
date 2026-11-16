//! iron-proxy YAML config rendering (plan step 6).
//!
//! Flow style throughout; every string that can hold a path, address, host pattern or
//! sentinel is emitted as a JSON string, which is a valid YAML double-quoted scalar.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use super::ProxyConfig;
use crate::paths::DataDirs;

/// Plan default for `proxy.upstream_deny_cidrs` (replaces iron-proxy's defaults).
pub const DEFAULT_DENY_CIDRS: &[&str] = &[
    "127.0.0.0/8",
    "::1/128",
    "0.0.0.0/8",
    "::/128",
    "169.254.169.254/32",
    "fd00:ec2::254/128",
];

/// Host rule of a blocked (ended) sentinel. `.invalid` never resolves, so the entry never
/// substitutes; the patched proxy then answers 403 for any request carrying the sentinel.
pub const BLOCKED_RULE_HOST: &str = "asm-ended-lease.invalid";

/// One active substitution entry.
pub struct RenderEntry<'a> {
    pub value_path: PathBuf,
    pub sentinel: &'a str,
    pub hosts: &'a [String],
}

pub struct RenderInput<'a> {
    pub cfg: &'a ProxyConfig,
    pub ca_cert: &'a Path,
    pub ca_key: &'a Path,
    pub entries: &'a [RenderEntry<'a>],
    /// Sentinels of ended leases; emitted as never-matching entries so they get the 403.
    pub blocked: &'a [String],
    /// Dummy value file for blocked entries (shorter than the 8-byte redaction minimum).
    pub blocked_value_path: &'a Path,
}

pub fn config_path(dirs: &DataDirs) -> PathBuf {
    dirs.proxy.join("iron-proxy.yaml")
}

pub fn listen_addr(bind: &str, port: u16) -> String {
    if bind.contains(':') && !bind.starts_with('[') {
        format!("[{bind}]:{port}")
    } else {
        format!("{bind}:{port}")
    }
}

fn q(s: &str) -> String {
    serde_json::to_string(s).expect("string serialisation cannot fail")
}

fn q_path(p: &Path) -> String {
    q(&p.to_string_lossy())
}

fn q_list<S: AsRef<str>>(items: &[S]) -> String {
    let parts: Vec<String> = items.iter().map(|s| q(s.as_ref())).collect();
    format!("[{}]", parts.join(", "))
}

pub fn render(input: &RenderInput<'_>) -> String {
    let c = input.cfg;
    let deny: Vec<String> = match &c.upstream_deny_cidrs {
        Some(v) => v.clone(),
        None => DEFAULT_DENY_CIDRS.iter().map(|s| s.to_string()).collect(),
    };
    let mut y = String::with_capacity(1024 + 320 * (input.entries.len() + input.blocked.len()));
    y.push_str("dns: {enabled: false}\n");
    y.push_str("proxy:\n");
    let _ = writeln!(
        y,
        "  http_listen: {}",
        q(&listen_addr("127.0.0.1", c.http_port))
    );
    let _ = writeln!(
        y,
        "  https_listen: {}",
        q(&listen_addr("127.0.0.1", c.https_port))
    );
    let _ = writeln!(y, "  tunnel_listen: {}", q(&listen_addr(&c.bind, c.port)));
    let _ = writeln!(y, "  max_request_body_bytes: {}", c.max_body);
    let _ = writeln!(y, "  upstream_deny_cidrs: {}", q_list(&deny));
    let _ = writeln!(
        y,
        "tls: {{mode: mitm, ca_cert: {}, ca_key: {}}}",
        q_path(input.ca_cert),
        q_path(input.ca_key)
    );
    let _ = writeln!(
        y,
        "management: {{listen: {}, api_key_env: IRON_MANAGEMENT_API_KEY}}",
        q(&listen_addr("127.0.0.1", c.mgmt_port))
    );
    let _ = writeln!(
        y,
        "metrics: {{listen: {}}}",
        q(&listen_addr("127.0.0.1", c.metrics_port))
    );
    y.push_str("log: {level: info}\n");
    if input.entries.is_empty() && input.blocked.is_empty() {
        y.push_str("transforms: []\n");
        return y;
    }
    y.push_str("transforms:\n  - name: secrets\n    config:\n      secrets:\n");
    let mut entry = |path: &Path, sentinel: &str, plain: bool, hosts: &[&str]| {
        let rules: Vec<String> = hosts
            .iter()
            .map(|h| format!("{{host: {}}}", q(h)))
            .collect();
        let _ = writeln!(
            y,
            "        - source: {{type: file, path: {}}}",
            q_path(path)
        );
        let _ = writeln!(
            y,
            "          replace: {{proxy_value: {}, match_body: true, match_path: true, match_query: true, allow_plain_http: {plain}}}",
            q(sentinel)
        );
        let _ = writeln!(y, "          rules: [{}]", rules.join(", "));
    };
    for e in input.entries {
        let hosts: Vec<&str> = e.hosts.iter().map(String::as_str).collect();
        entry(&e.value_path, e.sentinel, c.allow_plain_http, &hosts);
    }
    for s in input.blocked {
        entry(input.blocked_value_path, s, false, &[BLOCKED_RULE_HOST]);
    }
    y
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ProxyConfig {
        ProxyConfig::default()
    }

    #[test]
    fn renders_plan_layout_with_entries() {
        let hosts = vec![
            "api.github.com".to_string(),
            "*.githubusercontent.com".to_string(),
        ];
        let entries = [RenderEntry {
            value_path: PathBuf::from("/tmp/v/lease-1.0"),
            sentinel: "asm_0123456789012345678901234567890123456789",
            hosts: &hosts,
        }];
        let blocked = vec!["asm_ABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJ".to_string()];
        let out = render(&RenderInput {
            cfg: &cfg(),
            ca_cert: Path::new("/Users/a b/Library/Application Support/asm/proxy/ca.crt"),
            ca_key: Path::new("/Users/a b/Library/Application Support/asm/proxy/ca.key"),
            entries: &entries,
            blocked: &blocked,
            blocked_value_path: Path::new("/data/proxy/blocked.value"),
        });
        let expected = r#"dns: {enabled: false}
proxy:
  http_listen: "127.0.0.1:7413"
  https_listen: "127.0.0.1:7414"
  tunnel_listen: "0.0.0.0:7412"
  max_request_body_bytes: 10485760
  upstream_deny_cidrs: ["127.0.0.0/8", "::1/128", "0.0.0.0/8", "::/128", "169.254.169.254/32", "fd00:ec2::254/128"]
tls: {mode: mitm, ca_cert: "/Users/a b/Library/Application Support/asm/proxy/ca.crt", ca_key: "/Users/a b/Library/Application Support/asm/proxy/ca.key"}
management: {listen: "127.0.0.1:7415", api_key_env: IRON_MANAGEMENT_API_KEY}
metrics: {listen: "127.0.0.1:7416"}
log: {level: info}
transforms:
  - name: secrets
    config:
      secrets:
        - source: {type: file, path: "/tmp/v/lease-1.0"}
          replace: {proxy_value: "asm_0123456789012345678901234567890123456789", match_body: true, match_path: true, match_query: true, allow_plain_http: false}
          rules: [{host: "api.github.com"}, {host: "*.githubusercontent.com"}]
        - source: {type: file, path: "/data/proxy/blocked.value"}
          replace: {proxy_value: "asm_ABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJ", match_body: true, match_path: true, match_query: true, allow_plain_http: false}
          rules: [{host: "asm-ended-lease.invalid"}]
"#;
        assert_eq!(out, expected);
    }

    #[test]
    fn empty_entry_set_has_no_transforms_and_honours_overrides() {
        let c = ProxyConfig {
            bind: "::".into(),
            port: 9000,
            allow_plain_http: true,
            upstream_deny_cidrs: Some(vec!["192.0.2.0/24".into()]),
            ..cfg()
        };
        let out = render(&RenderInput {
            cfg: &c,
            ca_cert: Path::new("/c\"a.crt"),
            ca_key: Path::new("/ca.key"),
            entries: &[],
            blocked: &[],
            blocked_value_path: Path::new("/b"),
        });
        assert!(
            out.ends_with("log: {level: info}\ntransforms: []\n"),
            "{out}"
        );
        assert!(out.contains("  tunnel_listen: \"[::]:9000\"\n"));
        assert!(out.contains("  upstream_deny_cidrs: [\"192.0.2.0/24\"]\n"));
        assert!(out.contains("ca_cert: \"/c\\\"a.crt\""));
    }

    #[test]
    fn plain_http_flag_applies_to_active_entries_only() {
        let c = ProxyConfig {
            allow_plain_http: true,
            ..cfg()
        };
        let hosts = vec!["127.0.0.1".to_string()];
        let entries = [RenderEntry {
            value_path: PathBuf::from("/v/a.0"),
            sentinel: "asm_x",
            hosts: &hosts,
        }];
        let blocked = vec!["asm_y".to_string()];
        let out = render(&RenderInput {
            cfg: &c,
            ca_cert: Path::new("/ca.crt"),
            ca_key: Path::new("/ca.key"),
            entries: &entries,
            blocked: &blocked,
            blocked_value_path: Path::new("/b"),
        });
        assert_eq!(out.matches("allow_plain_http: true").count(), 1);
        assert_eq!(out.matches("allow_plain_http: false").count(), 1);
    }
}
