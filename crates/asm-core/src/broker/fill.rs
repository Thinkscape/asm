//! What the broker runs in the sign-in page and what it exports at hand-over: the
//! field finder, the fill function, origin rules, the cookie filter and the
//! Playwright-compatible storage state.

use asm_proto::ApiError;
use asm_proto::rules::parse_https_url;
use serde_json::{Value, json};

/// Field kinds, in fill priority order.
pub(crate) const KINDS: [&str; 3] = ["password", "username", "totp"];

/// Called with the kinds to look for (priority order) and the approved origins. Only in
/// the top-level document of an approved origin: marks one visible, enabled, empty, not
/// yet filled input with `data-asm-fill`. Returns `{origin, kind}` (`kind` null when
/// nothing was marked); the origin check runs in the same task as the marking.
pub(crate) const FIND_JS: &str = r#"function (kinds, origins) {
  const origin = location.origin;
  if (window !== window.top || !origins.includes(origin)) return { origin, kind: null };
  for (const old of document.querySelectorAll('[data-asm-fill]')) old.removeAttribute('data-asm-fill');
  const usable = (el) => {
    if (el.disabled || el.readOnly || el.value !== '' || el.hasAttribute('data-asm-filled')) return false;
    if (el.type === 'hidden') return false;
    const style = getComputedStyle(el);
    if (style.visibility === 'hidden' || style.display === 'none') return false;
    const box = el.getBoundingClientRect();
    return box.width > 0 && box.height > 0;
  };
  const autocomplete = (el) => (el.getAttribute('autocomplete') || '').toLowerCase().split(/\s+/);
  const named = (el, re) => re.test(el.name || '') || re.test(el.id || '');
  const oneTimeCode = (el) => autocomplete(el).includes('one-time-code');
  const matches = {
    password: (el) => el.type === 'password' && !oneTimeCode(el),
    username: (el) => ['text', 'email', 'tel'].includes(el.type) && !oneTimeCode(el)
      && (autocomplete(el).some((t) => t === 'username' || t === 'email') || el.type === 'email'
        || named(el, /user|email|login/i)),
    totp: (el) => ['text', 'tel', 'number', 'password'].includes(el.type)
      && (oneTimeCode(el)
        || ((named(el, /otp|totp|2fa|mfa|one.?time|verification|code/i)
          || /otp|totp|2fa|mfa|one.?time|verification|code/i.test(el.getAttribute('aria-label') || ''))
          && ((el.maxLength > 0 && el.maxLength <= 10) || el.inputMode === 'numeric'))),
  };
  const inputs = Array.from(document.querySelectorAll('input')).filter(usable);
  for (const kind of kinds) {
    const found = inputs.find(matches[kind]);
    if (found) {
      found.setAttribute('data-asm-fill', '');
      return { origin, kind };
    }
  }
  return { origin, kind: null };
}"#;

/// Selects the element [`FIND_JS`] marked.
pub(crate) const MARKED_JS: &str = "document.querySelector('[data-asm-fill]')";

/// Called on the marked element with the value and the approved origins. Fills only an
/// element of this world's own top-level document of an approved origin; returns whether
/// it filled. Never submits.
pub(crate) const FILL_FN: &str = "function(v, origins){if (window !== window.top || !origins.includes(location.origin) || !this.isConnected || this.ownerDocument !== document) return false; this.focus(); this.value=v; this.dispatchEvent(new Event('input',{bubbles:true})); this.dispatchEvent(new Event('change',{bubbles:true})); this.removeAttribute('data-asm-fill'); this.setAttribute('data-asm-filled',''); return true}";

/// `https://host[:port]`, omitting `:443`.
pub(crate) fn origin(host: &str, port: u16) -> String {
    if port == 443 { format!("https://{host}") } else { format!("https://{host}:{port}") }
}

/// The origin of an `https://` page URL, `None` for anything else.
pub(crate) fn https_origin(url: &str) -> Option<String> {
    parse_https_url(url).ok().map(|(host, port)| origin(&host, port))
}

/// An origin to show for any URL (`https://a.b`, `about:blank`, `chrome://newtab`).
pub(crate) fn display_origin(url: &str) -> String {
    if let Some(origin) = https_origin(url) {
        return origin;
    }
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
            format!("{scheme}://{authority}")
        }
        None => url.split(['?', '#']).next().unwrap_or(url).to_owned(),
    }
}

/// An extra fill origin from a request: exactly `https://host[:port]` (a trailing `/`
/// is accepted), canonicalized.
pub(crate) fn parse_fill_origin(s: &str) -> Result<String, ApiError> {
    let bad = || ApiError::invalid(format!("fill origin {s:?} must be https://host[:port]"));
    let (host, port) = parse_https_url(s).map_err(|e| ApiError::invalid(format!("fill origin {s:?}: {}", e.message)))?;
    let rest = s.get(8..).ok_or_else(bad)?;
    let rest = &rest[rest.find(['/', '?', '#']).unwrap_or(rest.len())..];
    if !rest.is_empty() && rest != "/" {
        return Err(bad());
    }
    Ok(origin(&host, port))
}

/// Whether a cookie from `Storage.getCookies` is valid for `host`: a host-only cookie
/// whose domain is `host`, or a domain cookie (`.d`) for `d` or a parent of `host`.
/// Partitioned cookies are never exported.
pub(crate) fn keeps_cookie(cookie: &Value, host: &str) -> bool {
    if cookie.get("partitionKey").is_some_and(|k| !k.is_null())
        || cookie.get("partitionKeyOpaque").and_then(Value::as_bool) == Some(true)
    {
        return false;
    }
    let Some(domain) = cookie["domain"].as_str() else { return false };
    let domain = domain.to_ascii_lowercase();
    match domain.strip_prefix('.') {
        Some(d) => !d.is_empty() && (host == d || host.strip_suffix(d).is_some_and(|p| p.ends_with('.'))),
        None => domain == host,
    }
}

/// The `Runtime.callFunctionOn` parameters that fill `value` into `object_id`, serialized
/// into a zeroized buffer sized up front (no other copy of `value` is made).
pub(crate) fn fill_call(object_id: &str, value: &str, origins: &[String]) -> zeroize::Zeroizing<Vec<u8>> {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Call<'a> {
        object_id: &'a str,
        function_declaration: &'a str,
        arguments: (Arg<&'a str>, Arg<&'a [String]>),
        return_by_value: bool,
        silent: bool,
    }
    #[derive(serde::Serialize)]
    struct Arg<T> {
        value: T,
    }
    // JSON escapes a byte as at most 6 bytes (`\u00XX`).
    let capacity = 256 + object_id.len() * 6 + FILL_FN.len() * 6 + value.len() * 6
        + origins.iter().map(|o| o.len() * 6 + 3).sum::<usize>();
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(capacity));
    let call = Call {
        object_id, function_declaration: FILL_FN,
        arguments: (Arg { value }, Arg { value: origins }), return_by_value: true, silent: true,
    };
    serde_json::to_writer(&mut *out, &call).expect("serializing to memory");
    debug_assert!(out.len() <= capacity);
    out
}

/// A Playwright `storageState`: the kept cookies, and the export origin's localStorage
/// (`entries` as returned by `DOMStorage.getDOMStorageItems`: `[[key, value], …]`).
/// Origins without localStorage are left out.
pub(crate) fn storage_state(cookies: &[Value], host: &str, export_origin: &str, entries: &[Value]) -> Value {
    let cookies: Vec<Value> = cookies.iter().filter(|c| keeps_cookie(c, host)).map(|c| json!({
        "name": c["name"].as_str().unwrap_or(""),
        "value": c["value"].as_str().unwrap_or(""),
        "domain": c["domain"].as_str().unwrap_or(""),
        "path": c["path"].as_str().unwrap_or("/"),
        "expires": c["expires"].as_f64().unwrap_or(-1.0),
        "httpOnly": c["httpOnly"].as_bool().unwrap_or(false),
        "secure": c["secure"].as_bool().unwrap_or(false),
        // Chromium omits SameSite when unspecified; browsers then treat it as Lax.
        "sameSite": c["sameSite"].as_str().unwrap_or("Lax"),
    })).collect();
    let local: Vec<Value> = entries.iter().filter_map(|e| match e.as_array().map(Vec::as_slice) {
        Some([Value::String(name), Value::String(value)]) => Some(json!({ "name": name, "value": value })),
        _ => None,
    }).collect();
    let origins = if local.is_empty() {
        Vec::new()
    } else {
        vec![json!({ "origin": export_origin, "localStorage": local })]
    };
    json!({ "cookies": cookies, "origins": origins })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cookie(name: &str, domain: &str) -> Value {
        json!({ "name": name, "value": "v", "domain": domain, "path": "/", "expires": -1, "size": 2,
            "httpOnly": true, "secure": true, "session": true, "priority": "Medium" })
    }

    #[test]
    fn cookie_filter_keeps_only_cookies_valid_for_the_export_host() {
        let host = "app.example.com";
        assert!(keeps_cookie(&cookie("a", "app.example.com"), host), "host-only, same host");
        assert!(!keeps_cookie(&cookie("b", "example.com"), host), "host-only, parent host");
        assert!(!keeps_cookie(&cookie("c", "other.app.example.com"), host), "host-only, child host");
        assert!(keeps_cookie(&cookie("d", ".example.com"), host), "domain cookie of a parent");
        assert!(keeps_cookie(&cookie("e", ".app.example.com"), host), "domain cookie of the host");
        assert!(!keeps_cookie(&cookie("f", ".other.example.com"), host), "domain cookie of a sibling");
        assert!(!keeps_cookie(&cookie("g", ".pp.example.com"), host), "suffix without a label boundary");
        assert!(!keeps_cookie(&cookie("h", ".evil.com"), host));
        assert!(!keeps_cookie(&cookie("i", "."), host));
        assert!(keeps_cookie(&cookie("j", "App.Example.com"), host), "domains compare case-insensitively");
        let mut partitioned = cookie("k", "app.example.com");
        partitioned["partitionKey"] = json!({ "topLevelSite": "https://example.com", "hasCrossSiteAncestor": false });
        assert!(!keeps_cookie(&partitioned, host), "partitioned cookies are dropped");
        partitioned["partitionKey"] = json!("https://example.com");
        assert!(!keeps_cookie(&partitioned, host), "older Chrome sends the key as a string");
        let mut opaque = cookie("l", "app.example.com");
        opaque["partitionKeyOpaque"] = json!(true);
        assert!(!keeps_cookie(&opaque, host), "opaque partitioned cookies are dropped");
        opaque["partitionKeyOpaque"] = json!(false);
        assert!(keeps_cookie(&opaque, host));
    }

    #[test]
    fn fill_call_carries_the_value_and_origins_as_arguments() {
        let secret = "p\"\\\u{1}ä\u{2028}";
        let origins = vec!["https://a.test".to_owned(), "https://b.test:8443".to_owned()];
        let call = fill_call("obj-1", secret, &origins);
        let parsed: Value = serde_json::from_slice(&call).unwrap();
        assert_eq!(parsed, json!({
            "objectId": "obj-1", "functionDeclaration": FILL_FN,
            "arguments": [{ "value": secret }, { "value": origins }],
            "returnByValue": true, "silent": true,
        }));
    }

    #[test]
    fn storage_state_has_the_playwright_shape() {
        let mut lax = cookie("sid", "app.example.com");
        lax["sameSite"] = json!("Strict");
        lax["expires"] = json!(1_900_000_000.5);
        let cookies = vec![lax, cookie("other", "other.test"), cookie("dom", ".example.com")];
        let entries = vec![json!(["token", "t"]), json!(["broken"]), json!(["theme", "dark"])];
        let state = storage_state(&cookies, "app.example.com", "https://app.example.com", &entries);
        assert_eq!(state, json!({
            "cookies": [
                { "name": "sid", "value": "v", "domain": "app.example.com", "path": "/", "expires": 1_900_000_000.5,
                  "httpOnly": true, "secure": true, "sameSite": "Strict" },
                { "name": "dom", "value": "v", "domain": ".example.com", "path": "/", "expires": -1.0,
                  "httpOnly": true, "secure": true, "sameSite": "Lax" },
            ],
            "origins": [{ "origin": "https://app.example.com", "localStorage": [
                { "name": "token", "value": "t" }, { "name": "theme", "value": "dark" },
            ] }],
        }));
        let empty = storage_state(&[], "app.example.com", "https://app.example.com", &[]);
        assert_eq!(empty, json!({ "cookies": [], "origins": [] }));
    }

    #[test]
    fn origins() {
        assert_eq!(https_origin("https://Example.com:443/login?x=1").as_deref(), Some("https://example.com"));
        assert_eq!(https_origin("https://example.com:8443/").as_deref(), Some("https://example.com:8443"));
        assert_eq!(https_origin("http://example.com/"), None);
        assert_eq!(https_origin("about:blank"), None);
        assert_eq!(display_origin("about:blank"), "about:blank");
        assert_eq!(display_origin("chrome://newtab/"), "chrome://newtab");
        assert_eq!(display_origin("http://example.com/x"), "http://example.com");
        assert_eq!(parse_fill_origin("https://SSO.example.com").unwrap(), "https://sso.example.com");
        assert_eq!(parse_fill_origin("https://sso.example.com:443/").unwrap(), "https://sso.example.com");
        assert_eq!(parse_fill_origin("https://sso.example.com:8443").unwrap(), "https://sso.example.com:8443");
        for bad in ["http://sso.example.com", "https://sso.example.com/login", "https://sso.example.com?x",
            "https://*.example.com", "https://10.0.0.1", "sso.example.com"] {
            assert!(parse_fill_origin(bad).is_err(), "{bad}");
        }
    }
}
