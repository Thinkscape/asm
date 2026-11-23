//! iron-proxy YAML config rendering (plan step 6).
//!
//! Flow style throughout; every string that can hold a path, address, host pattern or
//! sentinel is emitted as a JSON string, which is a valid YAML double-quoted scalar.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use super::{BrowserRoute, LoginBinding, ProxyConfig};
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

/// One active substitution entry.
pub struct RenderEntry<'a> {
    pub value_path: PathBuf,
    pub sentinel: &'a str,
    pub hosts: &'a [String],
    /// A single-use login entry (exactly one host); `claim_path` is then set.
    pub login: Option<&'a LoginBinding>,
    pub claim_path: Option<PathBuf>,
}

pub struct RenderInput<'a> {
    pub cfg: &'a ProxyConfig,
    pub ca_cert: &'a Path,
    pub ca_key: &'a Path,
    pub browser_ca_cert: &'a Path,
    pub browser_ca_key: &'a Path,
    /// `proxy.auth_file`, emitted only when `cfg.require_auth`.
    pub auth_file: &'a Path,
    pub entries: &'a [RenderEntry<'a>],
    /// Sentinels of ended leases; emitted as `ended: true` entries so they get the 403
    /// `asm: sentinel expired or revoked; run asm get again`.
    pub ended: &'a [String],
    /// `(host, port)` pairs a marked browser CONNECT may be routed to.
    pub routes: &'a [BrowserRoute],
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
    let mut y = String::with_capacity(
        1024 + 320 * input.entries.len() + 80 * input.ended.len() + 64 * input.routes.len(),
    );
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
    if c.require_auth {
        let _ = writeln!(y, "  auth_file: {}", q_path(input.auth_file));
    }
    let _ = writeln!(
        y,
        "tls: {{mode: mitm, ca_cert: {}, ca_key: {}, browser_ca_cert: {}, browser_ca_key: {}}}",
        q_path(input.ca_cert),
        q_path(input.ca_key),
        q_path(input.browser_ca_cert),
        q_path(input.browser_ca_key)
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
    // Always present: iron-proxy approves a marked browser CONNECT only through this
    // transform's `browser_hosts`, so an empty list keeps every browser route denied.
    y.push_str("transforms:\n  - name: secrets\n    config:\n");
    let hosts: Vec<String> = input
        .routes
        .iter()
        .map(|r| format!("{{host: {}, port: {}, until: {}}}", q(&r.host), r.port, r.until))
        .collect();
    let _ = writeln!(y, "      browser_hosts: [{}]", hosts.join(", "));
    if input.entries.is_empty() && input.ended.is_empty() {
        y.push_str("      secrets: []\n");
        return y;
    }
    y.push_str("      secrets:\n");
    for e in input.entries {
        let _ = writeln!(
            y,
            "        - source: {{type: file, path: {}}}",
            q_path(&e.value_path)
        );
        if let (Some(login), Some(claim)) = (e.login, &e.claim_path) {
            let _ = writeln!(
                y,
                "          replace: {{proxy_value: {}, login: {{port: {}, target: {}, owner: {}, claim_file: {}}}}}",
                q(e.sentinel),
                login.port,
                q(&login.target),
                q(&login.owner),
                q_path(claim)
            );
            let host = e.hosts.first().map(String::as_str).unwrap_or_default();
            let _ = writeln!(
                y,
                "          rules: [{{host: {}, methods: [\"POST\", \"PUT\", \"PATCH\"]}}]",
                q(host)
            );
            continue;
        }
        let rules: Vec<String> = e
            .hosts
            .iter()
            .map(|h| format!("{{host: {}}}", q(h)))
            .collect();
        let _ = writeln!(
            y,
            "          replace: {{proxy_value: {}, match_body: true, match_path: true, match_query: true, allow_plain_http: {}}}",
            q(e.sentinel),
            c.allow_plain_http
        );
        let _ = writeln!(y, "          rules: [{}]", rules.join(", "));
    }
    for s in input.ended {
        let _ = writeln!(
            y,
            "        - replace: {{proxy_value: {}, ended: true}}",
            q(s)
        );
    }
    y
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ProxyConfig {
        ProxyConfig::default()
    }

    fn entry<'a>(path: &str, sentinel: &'a str, hosts: &'a [String]) -> RenderEntry<'a> {
        RenderEntry {
            value_path: PathBuf::from(path),
            sentinel,
            hosts,
            login: None,
            claim_path: None,
        }
    }

    fn input<'a>(
        cfg: &'a ProxyConfig,
        entries: &'a [RenderEntry<'a>],
        ended: &'a [String],
        routes: &'a [BrowserRoute],
    ) -> RenderInput<'a> {
        RenderInput {
            cfg,
            ca_cert: Path::new("/ca.crt"),
            ca_key: Path::new("/ca.key"),
            browser_ca_cert: Path::new("/browser-ca.crt"),
            browser_ca_key: Path::new("/browser-ca.key"),
            auth_file: Path::new("/proxy-auth"),
            entries,
            ended,
            routes,
        }
    }

    #[test]
    fn renders_plan_layout_with_entries() {
        let hosts = vec![
            "api.github.com".to_string(),
            "*.githubusercontent.com".to_string(),
        ];
        let entries = [entry(
            "/tmp/v/lease-1.0",
            "asm_0123456789012345678901234567890123456789",
            &hosts,
        )];
        let ended = vec!["asm_ABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJ".to_string()];
        let out = render(&RenderInput {
            cfg: &cfg(),
            ca_cert: Path::new("/Users/a b/Library/Application Support/asm/proxy/ca.crt"),
            ca_key: Path::new("/Users/a b/Library/Application Support/asm/proxy/ca.key"),
            browser_ca_cert: Path::new("/Users/a b/Library/Application Support/asm/proxy/browser-ca.crt"),
            browser_ca_key: Path::new("/Users/a b/Library/Application Support/asm/proxy/browser-ca.key"),
            auth_file: Path::new("/Users/a b/Library/Application Support/asm/proxy/proxy-auth"),
            entries: &entries,
            ended: &ended,
            routes: &[],
        });
        let expected = r#"dns: {enabled: false}
proxy:
  http_listen: "127.0.0.1:7413"
  https_listen: "127.0.0.1:7414"
  tunnel_listen: "0.0.0.0:7412"
  max_request_body_bytes: 10485760
  upstream_deny_cidrs: ["127.0.0.0/8", "::1/128", "0.0.0.0/8", "::/128", "169.254.169.254/32", "fd00:ec2::254/128"]
tls: {mode: mitm, ca_cert: "/Users/a b/Library/Application Support/asm/proxy/ca.crt", ca_key: "/Users/a b/Library/Application Support/asm/proxy/ca.key", browser_ca_cert: "/Users/a b/Library/Application Support/asm/proxy/browser-ca.crt", browser_ca_key: "/Users/a b/Library/Application Support/asm/proxy/browser-ca.key"}
management: {listen: "127.0.0.1:7415", api_key_env: IRON_MANAGEMENT_API_KEY}
metrics: {listen: "127.0.0.1:7416"}
log: {level: info}
transforms:
  - name: secrets
    config:
      browser_hosts: []
      secrets:
        - source: {type: file, path: "/tmp/v/lease-1.0"}
          replace: {proxy_value: "asm_0123456789012345678901234567890123456789", match_body: true, match_path: true, match_query: true, allow_plain_http: false}
          rules: [{host: "api.github.com"}, {host: "*.githubusercontent.com"}]
        - replace: {proxy_value: "asm_ABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJ", ended: true}
"#;
        assert_eq!(out, expected);
    }

    #[test]
    fn empty_entry_set_keeps_an_empty_secrets_transform_and_honours_overrides() {
        let c = ProxyConfig {
            bind: "::".into(),
            port: 9000,
            allow_plain_http: true,
            upstream_deny_cidrs: Some(vec!["192.0.2.0/24".into()]),
            ..cfg()
        };
        let mut i = input(&c, &[], &[], &[]);
        i.ca_cert = Path::new("/c\"a.crt");
        let out = render(&i);
        assert!(
            out.ends_with(
                "log: {level: info}\ntransforms:\n  - name: secrets\n    config:\n      browser_hosts: []\n      secrets: []\n"
            ),
            "{out}"
        );
        assert!(out.contains("  tunnel_listen: \"[::]:9000\"\n"));
        assert!(out.contains("  upstream_deny_cidrs: [\"192.0.2.0/24\"]\n"));
        assert!(out.contains("ca_cert: \"/c\\\"a.crt\""));
        assert!(!out.contains("auth_file"), "proxy authentication is off by default");
    }

    #[test]
    fn ended_only_config_has_secrets_transform() {
        let ended = vec!["asm_y".to_string()];
        let c = cfg();
        let out = render(&input(&c, &[], &ended, &[]));
        assert!(
            out.ends_with(
                "transforms:\n  - name: secrets\n    config:\n      browser_hosts: []\n      secrets:\n        - replace: {proxy_value: \"asm_y\", ended: true}\n"
            ),
            "{out}"
        );
    }

    #[test]
    fn plain_http_flag_applies_to_active_entries_only() {
        let c = ProxyConfig {
            allow_plain_http: true,
            ..cfg()
        };
        let hosts = vec!["127.0.0.1".to_string()];
        let entries = [entry("/v/a.0", "asm_x", &hosts)];
        let ended = vec!["asm_y".to_string()];
        let out = render(&input(&c, &entries, &ended, &[]));
        assert_eq!(out.matches("allow_plain_http: true").count(), 1);
        assert_eq!(out.matches("allow_plain_http").count(), 1);
        assert_eq!(out.matches("ended: true").count(), 1);
    }

    #[test]
    fn renders_login_entry() {
        let hosts = vec!["login.example.com".to_string()];
        let binding = LoginBinding {
            port: 8443,
            target: "/session?return_to=%2F".into(),
            owner: "host-1".into(),
        };
        let entries = [RenderEntry {
            login: Some(&binding),
            claim_path: Some(PathBuf::from("/data/proxy/login-claims/lease-1.0.claim")),
            ..entry("/v/lease-1.0", "asm_login", &hosts)
        }];
        let c = ProxyConfig {
            allow_plain_http: true,
            ..cfg()
        };
        let out = render(&input(&c, &entries, &[], &[]));
        assert!(
            out.ends_with(concat!(
                "      secrets:\n",
                "        - source: {type: file, path: \"/v/lease-1.0\"}\n",
                "          replace: {proxy_value: \"asm_login\", login: {port: 8443, target: \"/session?return_to=%2F\", owner: \"host-1\", claim_file: \"/data/proxy/login-claims/lease-1.0.claim\"}}\n",
                "          rules: [{host: \"login.example.com\", methods: [\"POST\", \"PUT\", \"PATCH\"]}]\n",
            )),
            "{out}"
        );
        assert!(!out.contains("allow_plain_http"), "login entries take only proxy_value, login and rules");
    }

    #[test]
    fn renders_browser_hosts() {
        let routes = [
            BrowserRoute { host: "login.example.com".into(), port: 443, until: 1_800_000_000 },
            BrowserRoute { host: "b.example.com".into(), port: 8443, until: 1_800_000_060 },
        ];
        let c = cfg();
        let out = render(&input(&c, &[], &[], &routes));
        assert!(
            out.contains(
                "      browser_hosts: [{host: \"login.example.com\", port: 443, until: 1800000000}, {host: \"b.example.com\", port: 8443, until: 1800000060}]\n      secrets: []\n"
            ),
            "{out}"
        );
    }

    #[test]
    fn renders_auth_file_and_browser_ca() {
        let c = ProxyConfig {
            require_auth: true,
            ..cfg()
        };
        let out = render(&input(&c, &[], &[], &[]));
        assert!(
            out.contains(
                "  upstream_deny_cidrs: [\"127.0.0.0/8\", \"::1/128\", \"0.0.0.0/8\", \"::/128\", \"169.254.169.254/32\", \"fd00:ec2::254/128\"]\n  auth_file: \"/proxy-auth\"\ntls: {mode: mitm, ca_cert: \"/ca.crt\", ca_key: \"/ca.key\", browser_ca_cert: \"/browser-ca.crt\", browser_ca_key: \"/browser-ca.key\"}\n"
            ),
            "{out}"
        );
    }
}
