# Browser logins with operator-held credentials (asm) — v4

## Context

Agents need to sign in to websites inside the browsers their tools already drive, using vault logins, without the real password ever reaching the model. Where the browser runs on a machine other than the manager Mac, the password also never reaches that machine.

The browsers in scope:
- the user's Chrome profile, driven by the Codex desktop Chrome extension, the omp relay or chrome-devtools-mcp;
- T3 Code server preview tabs;
- OpenBot named browser profiles.

End state:
- **Login grant.** `asm get --login-url FORM_ACTION_URL [ITEM] --reason TEXT` takes one approval and returns:
  - the username;
  - a single-use password sentinel, which iron-proxy on the Mac substitutes only in that exact HTTPS form submission;
  - the current TOTP code. Later TOTP codes come without a popup until the grant expires.
- **Proxy.** iron-proxy rejects out-of-scope sentinels in request bodies, escapes substituted values according to content type, and offers opt-in per-host proxy authentication.
- **Router.** `asm proxy-router` runs on 127.0.0.1 on each browser machine and sends only granted sites to the manager proxy. `asm browser install chrome|t3code|openbot` installs it.
- **Browser CA.** A dedicated asm browser CA is installed once and never changes. iron-proxy issues certificates from it only for routed, granted (host, port) pairs.
- **Broker.** `asm login` lets the operator sign in on the Mac and hands the agent a storageState for the approved site.

Verified with probes (Linux; Chrome 154; T3's chrome-headless-shell 157; temporary profiles):
- **Full Chrome** honors asm-written `<profile>/ServerCertificate` rows (real chain validation) and a `proxy` pref with a `data:` PAC in `<profile>/Preferences`, which persists across restarts on Linux.
- **chrome-headless-shell** ignores both files. It honors `--proxy-server` and a private NSS DB selected by `XDG_DATA_HOME`.
- **T3 wrapper.** A copy of the shell's version directory runs from a new path and loads its resources (ICU data).
- **No fallback after an answered CONNECT.** Chrome doesn't fall back when the proxy answers CONNECT with 502, 403 or 407. It does fall back when the proxy closes without a response.
- **Electron apps** trust only the OS store.
- **Root CA.** The asm root can't sign intermediates (`MaxPathLen 0`).
- **No SPKI pinning.** `--ignore-certificate-errors-spki-list` is never used: it accepts any chain that merely contains the pinned key.

## Approach

Order:
- Steps 1–4 (Go) are independent of the Rust work.
- Step 5 precedes 6–13.
- Step 10 precedes 11–12.
- Run each phase's tests before continuing.

### 1. iron-proxy: body scanning and content-type-aware substitution
Files: `third_party/iron-proxy/internal/transform/body.go`, `internal/transform/secrets/secrets.go`, and a new `internal/transform/secrets/body.go`.
- **`transform/body.go`.** Add `func (b *BufferedBody) MaxBytes() int64 { return b.maxBytes }` (0 = unlimited).
- **New `secrets/body.go`** (nothing equivalent exists):
  - `type bodyKind int` with values `bodyOther`, `bodyForm`, `bodyJSON`, `bodyMultipart`.
  - `func requestBodyKind(req *http.Request) bodyKind` classifies via `mime.ParseMediaType` on Content-Type:
    - `application/x-www-form-urlencoded` → form;
    - `application/json` or a `+json` suffix → json;
    - `multipart/form-data` → multipart;
    - anything else → other.
  - `func scannableBody(req *http.Request) (data []byte, ok bool, err error)`:
    - Returns data only when `req.Body` is a `*transform.BufferedBody` and the body carries no `Content-Encoding` other than `identity`.
    - Size rule: either `0 <= req.ContentLength <= MaxBytes()` (or `MaxBytes()==0`), or `ContentLength < 0` with kind form or json.
    - Read with `bb.Reset(); io.ReadAll(bb); bb.Reset()`. A truncated body gives `ok=false`; a nil body gives `nil, false, nil`.
    - Doc comment: scanning for out-of-scope sentinels is best effort. Over-limit, unknown-length non-form/JSON and content-encoded bodies aren't scanned. Login entries (step 2) fail closed instead.
  - `func escapeReal(kind bodyKind, real string) string`:
    - form → `url.QueryEscape(real)`;
    - json → the JSON string encoding without its surrounding quotes (`json.Encoder` with `SetEscapeHTML(false)`, trailing newline trimmed);
    - other → `real` unchanged.
- **`TransformRequest`.** When `s.hasReplace || len(s.ended) > 0`, call `scannableBody` once at the top. On `err`, return `rejectResult(req, 400, msgBodyUnreadable)` with `msgBodyUnreadable = "asm: request body could not be read"`.
- **`sentinelInRequest(req, pv string, body []byte)`.** Additionally return true when `body != nil && bytes.Contains(body, []byte(pv))`. Update the doc comment and both callers (the ended loop and the not-valid branch).
- **`swapBody`.** Replace `bytes.ReplaceAll(data, pv, real)` with `bytes.ReplaceAll(data, pv, []byte(escapeReal(requestBodyKind(req), real)))`.

### 2. iron-proxy: login entries (exact form action, whole value, durable single use)
**Config:**
- `replaceConfig` gets `Login *loginConfig \`yaml:"login,omitempty"\``.
- `type loginConfig struct { Port int \`yaml:"port"\`; Target string \`yaml:"target"\`; Owner string \`yaml:"owner"\`; ClaimFile string \`yaml:"claim_file"\` }`. `Target` is the escaped path plus `?query` when present. `Owner` is a paired host ID.
- `resolvedSecret` gets `login *loginConfig`.

**Validation (`newFromConfig`):**
- `port` is 1–65535.
- `target` starts with `/`.
- `owner` and `claim_file` (an absolute path) are non-empty.
- `rules` has exactly one rule: one host, no CIDR, methods `["POST","PUT","PATCH"]`.
- `match_*`, `require` and `allow_plain_http` are unset. Otherwise fail with `secrets[%d]: login entries take only proxy_value, login and rules`.

**Messages:**
- `msgLoginRequest = "asm: login sentinel not valid for %s %s"`
- `msgLoginValue = "asm: login sentinel must be an entire form or JSON value, sent once"`
- `msgLoginBody = "asm: login body must be application/x-www-form-urlencoded or JSON without Content-Encoding"`
- `msgLoginMulti = "asm: one login grant per request"`
- `msgLoginUnavailable = "asm: login secret unavailable"`
- `msgLoginOwner = "asm: this login grant belongs to another machine"`

**`TransformRequest` login phase** (runs before the generic replace loop):
1. **Collect hits.** `hits` = login entries whose sentinel appears in the headers, path, query or scanned body. More than one hit → reject 403 `msgLoginMulti`.
2. **Endpoint match.** An entry is an *endpoint match* when all of these hold:
   - `req.TLS != nil`;
   - `hostmatch.MatchAnyRule` (host and method);
   - the effective port (from `req.Host`, else 443) equals `Port`;
   - `req.URL.EscapedPath() + optional("?"+req.URL.RawQuery) == Target`, byte for byte.
3. **Unscannable bodies.** An endpoint-matching login entry outside `hits` with an unscannable body (`Content-Encoding` other than identity, `ok=false`, or a kind other than form/JSON) → reject 403 `msgLoginBody`.
4. **Processing the hit:**
   1. Not an endpoint match → 403 `fmt.Sprintf(msgLoginRequest, req.Method, scheme+"://"+host+":"+port+requestTarget)`, annotated `reject_reason=login_scope`.
   2. Sentinel in the headers, path or query (`sentinelInRequest(req, pv, nil)`) → `msgLoginValue`.
   3. Unscannable body or other kind → `msgLoginBody`.
   4. **Owner check.** When `tctx.TunnelUser != ""` (set by proxy auth, step 3) and it differs from `Owner` → 403 `msgLoginOwner`. With proxy auth off, the sentinel is a bearer capability, the same as exec sentinels.
   5. `sec.source.Get` error → 503 `msgLoginUnavailable`. Never forward.
   6. `swapLoginForm`/`swapLoginJSON` returns `!ok` → `msgLoginValue`.
   7. **Claim.** `os.OpenFile(ClaimFile, O_WRONLY|O_CREATE|O_EXCL, 0600)`. Write the RFC3339 time, `f.Sync()`, fsync the parent directory. Any error, including `EEXIST` → 403 `msgSentinelEnded`, annotated `sentinel_ended`. The claim happens before forwarding, so an indeterminate upstream outcome still consumes the grant.
   8. Install the new body (as in `swapBody`). Append `secretRecord{Secret: name, Locations: ["body"]}`, call `addRedactPair`, and delete `Range`/`If-Range`.
5. **Separation.** Login entries never take part in the generic replace loop.

**`swapLoginForm`.**
- The raw body must contain the sentinel exactly once.
- Split on `&`, then each segment at its first `=`, and `url.QueryUnescape` both halves.
- Exactly one segment may have a decoded value equal to the sentinel. Its name must not contain the sentinel.
- Replace that segment with `rawName + "=" + url.QueryEscape(real)`. Other segments stay byte-identical.

**`swapLoginJSON`.**
- The raw body must contain the sentinel exactly once.
- Walk with `json.Decoder` (`UseNumber`), tracking key versus value position in objects. The sentinel must be an entire string **value**, not a key. The raw token ending at `dec.InputOffset()` must be `"` + sentinel + `"`. The decoder must reach EOF cleanly.
- Replace the token bytes with the JSON encoding of `real` (`SetEscapeHTML(false)`).

### 3. iron-proxy: proxy authentication and the tunnel user
- **Config.**
  - `config.go` `Proxy` gets `AuthFile string \`yaml:"auth_file"\`` (absolute path when set; checked in `Validate`).
  - Plumb it through `cmd/iron-proxy/main.go` (`proxy.New`, ~L257) into `Options.AuthFile` and `Proxy.authFile`.
- **New `internal/proxy/proxyauth.go`:**
  - `func (p *Proxy) authRequired() bool`.
  - `func (p *Proxy) checkCredentials(user, pass string) bool` re-reads `authFile` on every call. Lines are `<user>:<hex sha256(pass)>`, compared with `subtle.ConstantTimeCompare`. A missing file means false.
  - `func (p *Proxy) authUser(h http.Header) (string, bool)` handles Basic `Proxy-Authorization`.
- **`tunnel.go`, when `authRequired()`:**
  - In `handleTunnelCONNECT` (~L94) and the absolute-form branch of `serveTunnelProxyHTTP` (~L77), without valid credentials respond `HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="asm"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n` and close.
  - In `handleSOCKS5` (~L141), accept only method 0x02 (reply `05 02`) and use the RFC 1929 sub-negotiation. Success → `01 00`; failure → `01 01`, then close.
- **No auth file** → behavior unchanged.
- **Tunnel user.**
  - Store the authenticated user in `transform.TunnelInfo.AuthUser`.
  - Add `TunnelUser string` to `transform.TransformContext`.
  - Set it from the tunnel's `TunnelInfo` on every inner request handled inside that CONNECT/SOCKS tunnel. Find where inner-request contexts are built with `rg -n "TransformContext\{" internal/proxy`.
  - Absolute-form requests set it from their own header.
- **Scope.** Auth covers only the tunnel listener. `http_listen`/`https_listen` bind 127.0.0.1 on the Mac.

### 4. iron-proxy: browser CA, route marker, default-deny issuance
- **Config.**
  - `config.go` `TLS` gets `BrowserCACert string \`yaml:"browser_ca_cert"\`` and `BrowserCAKey string \`yaml:"browser_ca_key"\``.
  - `Validate` requires both or neither: `tls.browser_ca_cert and tls.browser_ca_key must be set together`.
  - `main.go`: when both are set in MITM mode, build `certcache.New(cfg.TLS.BrowserCACert, cfg.TLS.BrowserCAKey, cfg.TLS.CertCacheSize, leafExpiry)` next to the existing cache (~L179) and pass it as `Options.BrowserCertCache` → `Proxy.browserCertCache`.
- **`tunnel.go` `handleTunnelCONNECT`:**
  - `browser := req.Header.Get("Asm-Browser-Route") == "1"`. Any other non-empty value → 403 `asm: invalid browser route marker`.
  - Run the auth check (step 3), then `tunnelTransformCheck`.
  - When `browser`, all of these apply:
    - `p.browserCertCache` must be non-nil; otherwise 403 `asm: browser routing is not enabled on this manager`.
    - `tunnelInfo.RequestTransforms` must contain a trace named `secrets` annotated `browser_route == "allowed"`; otherwise 403 `asm: no active login grant routes this host through asm`. This is default deny: with no secrets transform, nothing is allowed.
    - Pass `(cache, browser, target)` through `serveTunnelWithReader(conn, br, target, info, cache, browser)` (~L351) to `serveTunnelTLS(..., cache, browser)` (~L377). `serveTunnel` (SOCKS5) passes `p.certCache, false`.
    - A first byte other than `0x16` closes the connection.
    - `GetCertificate` is a closure over `cache`. It applies the same checks as `getCertificate` (proxy.go ~L251) and also requires `strings.EqualFold(hello.ServerName, hostOnly(target))`.
    - An inner request whose `Host` hostname or port (default 443) differs from `target` → 421 `asm: request authority does not match the browser route`.
- **`proxy.go`.**
  - Add `"Asm-Browser-Route"` to `hopByHopHeaders` (~L720).
  - Absolute-form or direct requests carrying the marker → 403 `asm: invalid browser route marker`.
- **`secrets.go`.**
  - `secretsConfig` gets `BrowserHosts []browserHostConfig \`yaml:"browser_hosts"\``, with `type browserHostConfig struct { Host string \`yaml:"host"\`; Port int \`yaml:"port"\`; Until int64 \`yaml:"until"\` }`. Validation: lowercase host, port 1–65535, `until > 0`.
  - At the top of `TransformRequest`, for `req.Method == CONNECT` with marker `1`:
    - If an entry matches the host (`strings.ToLower(hostOnly(req.Host))`), the port, and `time.Now().Unix() < Until`, then `tctx.Annotate("browser_route", "allowed")` and continue.
    - Otherwise reject 403 `"asm: no active login grant routes this host through asm"`, annotated `reject_reason=browser_route`.

### 5. Wire and shared helpers (`crates/asm-proto`)
**`wire.rs`:**
- **Capabilities.** `CAPABILITY_LOGIN_GRANT_V1 = "login_grant_v1"`, `CAPABILITY_LOGIN_BROKER_V1 = "login_broker_v1"`.
- **`LoginScope { pub url: String }`.**
- **`RequestBody::Get` gets `login: Option<LoginScope>`.**
  - With `login` set, `name` may be empty, meaning "infer".
  - `canonicalize` rejects `raw`, `fields`, non-empty `hosts`, `generation`, `lease_id`, `refresh` and `new_lease`, each with an `invalid` naming the flag.
  - It replaces `login.url` with `parse_login_url(..)?.canonical_url()`.
  - `validate_get_capabilities`: `login` requires the login capability.
- **`GetResult.login` and `LeaseInfo.login`:** `Option<LoginScope>`.
- **`ProxyInfo`** gets `proxy_auth: bool` (skipped when false) and `browser_ca_pem: Option<String>`.
- **`RequestBody::Login`** `{ name, url, reason, #[serde(default)] extra_fill_origins: Vec<String>, #[serde(default)] agent, #[serde(default)] client_capabilities }`, plus `RequestKind::Login`.

**`rules.rs`.** `pub struct LoginTarget { pub host: String, pub port: u16, pub target: String }`, with `canonical_url()` and `pub fn parse_login_url(url: &str) -> Result<LoginTarget, ApiError>` (`ApiError::invalid`):
- **Scheme:** `https://` only. No userinfo or `#`.
- **Host:** passes `normalize_host_pattern`, contains no `*?[`, and isn't an IP literal (`login grants need a DNS host name`).
- **Port:** defaults to 443; 1–65535.
- **Target:** path plus optional `?query`. It starts with `/` and is printable ASCII without whitespace. `%` escapes stay verbatim.
- **Canonical form:** `https://host[:port]<target>`, omitting `:443`.

Also add `parse_https_url(url) -> Result<(String, u16), ApiError>` for the broker. It applies the same host rules and allows any path.

**`crypto.rs`:**
- `pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32]`: RFC 2104 over `sha2`.
- `pub fn proxy_password(token_hash: &[u8; 32]) -> String { hex_encode(&hmac_sha256(token_hash, b"asm proxy auth v1")) }`.

### 6. `totp` field
**New `crates/asm-core/src/totp.rs`** (nothing equivalent exists; HMAC via `ring::hmac`):
- `enum TotpAlgorithm { Sha1, Sha256, Sha512 }` and `struct TotpKey { secret: Vec<u8>, algorithm, digits: u32, period: u64 }`.
- `parse(s) -> Result<TotpKey, String>`:
  - `otpauth://totp/...`: `secret` required; `algorithm` SHA1/SHA256/SHA512, default SHA1; `digits` 6–10, default 6; `period` 15–300, default 30.
  - `otpauth://hotp` and `steam://` → `unsupported authenticator key`.
  - Anything else is a bare base32 key: strip spaces, `-` and `=`, uppercase, then decode with a local RFC 4648 decoder.
- `code_at(&TotpKey, unix: u64) -> String`: RFC 6238 truncation, zero-padded.
- `current_code(&TotpKey, now: u64) -> String`: if fewer than 5 s remain in the step, return the **next** step's code. It never sleeps.

**`vault/bitwarden.rs`:**
- Add `Source::Totp`.
- `field_sources`, for `TYPE_LOGIN` after `password`: push `("totp", Source::Totp, seed)` when `login.totp` is non-empty and `totp::parse` succeeds.
- Skip custom fields named exactly `totp`; that name is reserved.
- `read` (~L1415) maps `Source::Totp` through `totp::current_code(&key, now)`. The seed never leaves the provider.
- `set_field` on `totp` → `CoreError::invalid("totp is generated from the item's authenticator key and cannot be updated")`.
- Update `maps_login_item`, and add a fixture with `login.totp = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"`.

**`manager/requests.rs`:** `substitutes(field)` becomes `!matches!(field, "username" | "totp")`.

### 7. Manager: login grants, claims, browser CA, routes
**Item inference.**
- In `crates/asm-core/src/manager/catalog.rs`, add `pub(crate) fn vault_logins_for_host(&self, host_id: &str, url_host: &str) -> Result<Vec<NamedSecret>>`, reusing the visibility rules of the `/secrets` listing.
- It returns `SecretKind::Login` items whose `meta.uri_hosts` contain `url_host` exactly. Only if there are none does it return items whose `uri_hosts` contain a parent domain of `url_host`.

**`create_get` with `login`:**
1. Parse the URL. If `name` is empty, infer the item:
   - zero candidates → `invalid("no vault login item has a URI for <host>; pass ITEM")`;
   - several → `invalid("several vault logins match <host>: <names>; pass ITEM")`.
2. The item must be `SecretKind::Login` with a `password` field.
3. `wanted_fields` = `username` (if present) + `password` + `totp` (if present).
4. Skip `get_shortcut`.
5. `initial = vec![target.host]`, `suggestions = vec![]`.
6. Include `login` in the `push_pending` dedupe closure.

With a generated secret → `invalid("login grants need a vault secret")`.

**`get_shortcut`.** Candidate filter adds `&& (l.login.is_none() || wanted_fields.iter().all(|f| !substitutes(f)))`. Plain-only requests (for example `ITEM::totp`) may then reuse an active login lease, with fresh codes and no popup until it ends. The single-use password sentinel is never redelivered.

**`approve_get` with `g.login`:**
- Mode must be Sentinel, else `Fail::Keep("a login grant delivers a sentinel; choose Proxied")`.
- `duration_secs` must be `Some(d)` with `d <= 3600`, else `Fail::Keep("a login grant lasts at most 1 hour")`.
- Hosts = `[target.host]`. The password `ProxyEntry` gets `login: Some(LoginBinding{port, target, owner: p.host_id})`.
- `LeaseRecord.login` and `GetResult.login` are set. Don't call `replace_secret_hosts`.

**`pending_to_ffi`.** Fill `login`; `default_duration_secs = Some(900)`.

**`store.rs`.** `LeaseRecord.login: Option<LoginScope>`. Add column `login TEXT`, both in `SCHEMA` and in the lease-column migration loop (~L1233–1250), stored as JSON like `generation`.

**Durable claims (the only record of use).**
- Location: `dirs.proxy.join("login-claims")` (0700), created in `ProxySupervisor::prepare`. It's outside the temp-dir `values` path, so `prune_values` never touches it.
- Claim file name: `format!("{}.claim", value_file_name(&lease_id, index))`.
- `prepare` deletes claim files whose lease no longer exists or ended more than 1 h ago; it gets a `&Store` reference for the check.
- Login entries stay in the config until the lease ends. A second use hits `EEXIST` (403 ended), and response redaction stays active for the whole window.
- There's no consumption state in the database. The activity log already records the swap through the existing proxy request event.

**Browser CA.** New `crates/asm-core/src/proxy/browser_ca.rs`, using rcgen 0.14 with ECDSA P-256 (the ring backend can't generate RSA):
- `pub fn ensure(proxy_dir: &Path) -> Result<CaPaths>` writes `browser-ca.crt` (0644) and `browser-ca.key` (0600 via `files::write_private_atomic`). If only one of the two exists, delete it and regenerate.
- Certificate:
  - CN `Agents Secrets Manager Browser CA`;
  - `IsCa::Ca(BasicConstraints::Constrained(0))`;
  - key usages `KeyCertSign`, `CrlSign`;
  - valid from now − 1 day to now + 10 years, via `rcgen::date_time_ymd` with the date parsed from `asm_proto::time::fmt_unix(now)`;
  - a random 16-byte serial.
- Call it in `ProxySupervisor::prepare` (~proxy/mod.rs L206), and add `pub fn browser_ca_pem(&self)`.

**`proxy/mod.rs`:**
- `pub struct LoginBinding { pub port: u16, pub target: String, pub owner: String }`; `ProxyEntry.login: Option<LoginBinding>`.
- `pub struct BrowserRoute { pub host: String, pub port: u16, pub until: i64 }`.
- **Desired snapshot.** The supervisor state stores `routes` next to `entries`. `apply`, `apply_deferred`, `apply_after_stopping_deferred` and `apply_locked` take `routes: Vec<BrowserRoute>`, and `write_config` reads `st.routes`. This way activation, `set_config` rollback (~L389–425) and spawn retry (~L605–624) all render the same routes. Update callers found by `rg -n "apply_deferred\(|apply_after_stopping_deferred\(|\.apply\(|apply_locked\(|\.activate\(|write_config\(" crates/asm-core/src`.
- `validate_entries`: a login entry has exactly one host.

**`proxy/config.rs` `render`:**
- `RenderInput` gets `browser_ca_cert`, `browser_ca_key` and `routes`. `RenderEntry` gets `login` and `claim_path`.
- The `tls:` line adds the browser CA paths.
- Always emit the `secrets` transform, even when empty: `config: {browser_hosts: [...], secrets: [...]}`.
- Login entries render as `replace: {proxy_value, login: {port, target, owner, claim_file}}` with `rules: [{host, methods: ["POST","PUT","PATCH"]}]`.
- Update the golden tests and add `renders_login_entry` and `renders_browser_hosts`.

**`manager/mod.rs`:**
- `ProxyState.routes` is recomputed in `publish_proxy_locked` (~L766) from `active` leases with `login`, with `until = expires_at`. Mark it dirty on change and pass it to `apply_deferred`.
- In `lease_entries` (~L226), convert `login` into `ProxyEntry.login`. On a parse failure, skip the entry and `log::error!`.

**`manager/api.rs`.**
- `health` adds the login capability.
- `proxy_info` fills `browser_ca_pem` and `proxy_auth`.
- No new endpoints.

**FFI and Swift:**
- FFI: `LoginScopeInfo { url }`; `RequestDetail::Get` gets `login: Option<LoginScopeInfo>`, appended last.
- `Models.swift`: `GetDetail.login`. `CoreBridge.swift` (~L421–444): positional destructuring in the same order.
- **`ApprovalViews.swift` `StaticGetApproval`**, when `login != nil`:
  - Show "Sign-in: \(url) · username, single-use password\(hasTotp ? ", one-time codes" : "") · routes this site through asm until the grant expires".
  - Hide `HostsSection` and Any-host.
  - Force `.proxied` and disable Raw in `AllowSplitButton`.
  - `GetDurationPicker` gets a new parameter `maxSeconds: UInt64?`: 3600 here, default selection 15 min.

### 8. Proxy authentication (opt-in) in manager and CLI
**Settings.** Follow the `allow_plain_http` checklist:
- `settings.rs`: `PROXY_REQUIRE_AUTH = "proxy.require_auth"` in `KEYS`, `load`, `save_proxy` and `seed`.
- `ProxyConfig.require_auth: bool`, default `false`.
- `ffi::ProxySettings.require_auth`, plus the admin get/set (~admin.rs L891–958).
- Swift: `ProxySettingsItem.requireAuth`, both `CoreBridge` inits, and a `ProxyPane` toggle "Require proxy authentication". Caption: "Each paired host signs in to the proxy with its own credentials, and login grants only work from the machine that requested them. Hosts running an asm CLI older than this release can no longer use the proxy."
- `render` emits `auth_file: "<dirs.proxy>/proxy-auth"` under `proxy:` when on.

**Credentials file:**
- `store.rs`: `pub fn active_host_token_hashes(&self) -> Result<Vec<(String, [u8; 32])>>`.
- `proxy/mod.rs`: `pub fn write_auth_users(&self, users: &[(String, [u8; 32])]) -> Result<()>` writes `"{id}:{sha256_hex(proxy_password(&hash))}\n"` lines via `files::write_private_atomic`.
- `Core::sync_proxy_auth()` runs at startup and after every host change. Find the call sites with `rg -n "insert_host|rotate_host_token|revoke_host|consume_pairing_code" crates/asm-core/src/manager`.
- On a sync failure, write an empty file (deny all) and log `Category::Proxy` `"auth_sync_failed"`.

**CLI `proxy.rs`:**
- `Resolved` keeps `proxy_auth`. When true, `exports`/`environment` use `http://{host_id}:{password}@{authority}` and `socks5h://…`, with `password = proxy_password(&sha256(host.token))`.
- `proxy-info` prints URLs without credentials, plus `auth: per-host credentials (added by asm exec, asm proxy-env and the proxy router)`.
- `doctor`'s HTTPS probe uses `reqwest::Proxy::basic_auth`.

### 9. `asm get --login-url`
**`GetArgs`:**
- Positionals become `name: Option<String>` and `reason: Option<String>`.
- Add `--reason TEXT` (conflicts with a positional reason) and `--login-url URL`.
- Without `--login-url`, both NAME and REASON are required (positional or flag). The error keeps the current usage text.
- With `--login-url`:
  - NAME is optional, and the reason comes from `--reason` or the second positional.
  - Conflicts with `--raw`, `--sentinel`, `--hosts`, `--lease`, `--refresh`, `--new-lease`, the generation flags, and a `::FIELD` binding (`invalid("--login-url takes a whole login item")`).
  - Validate early with `parse_login_url`.

**Co-location.** Before submitting, check the router status over `<config>/router.sock` (step 10). Not running → `failure("no asm proxy-router on this machine; the browser must run on this machine: asm browser install <target>")`.

**After approval, before writing files:**
1. **Check the grant.** Require `result.login == Some(canonical)`, `mode == Sentinel`, `hosts == [host]`, `expires_at` set, and files = `password` (substituted) + `username`/`totp` (plain) when present. Otherwise fail with `the manager returned a different login grant than requested`.
2. **Route barrier.**
   1. Resolve the proxy with `proxy::resolve_for`.
   2. Every 500 ms for up to 10 s, open TCP to the recommended proxy and send `CONNECT host:port HTTP/1.1\r\nHost: host:port\r\nAsm-Browser-Route: 1\r\n` (plus `Proxy-Authorization` when `proxy_auth`) + `\r\n`. Read the status line and close.
   3. `200` → push the route: `POST /routes` on the router socket with `{host, port, until, proxy: "<hint>:<port>"}`.
   4. Still 403 after 10 s → fail with `the proxy did not activate the route; run asm doctor`. The files are written anyway, and their paths are printed.
3. **Output.**
   - Text: `login: {url} (single use; routed through asm until {expires})`; JSON includes `login`.
   - stderr: `open or reload the login page now, type the username and the sentinel, submit once; for a one-time code run: asm get <ITEM>::totp --reason "<reason>"`.

### 10. `asm proxy-router` (hidden; installed by `asm browser install`)
**Files and wiring:**
- New `crates/asm-cli/src/router.rs` and `service.rs`.
- `main.rs` gets the hidden `#[command(hide = true, name = "proxy-router")] ProxyRouter(router::RouterCommand)` with `Run { --port u16 (default 7418) }` and `Status { --json }`.
- New `asm-cli` deps: `tokio = { workspace = true, features = ["rt-multi-thread", "net", "io-util", "time", "macros", "sync"] }`, `httparse = "1"`, `base64 = "0.22"`.

**`run`** (tokio):
- **Startup:**
  1. Take a flock on `<config>/router.lock` (`already running` → exit 0).
  2. Load `HostState`.
  3. Bind `127.0.0.1:<port>`, and `<config>/router.sock`: remove any stale file, bind, `chmod 0600`.
  4. Load routes from `<config>/router-routes.json` (0600), dropping any whose `until` has passed.
- **Route state.** `RwLock<{routes: Vec<{host, port, until, proxy}>, last_error, last_routed}>`, plus a tunnel registry (`id → (host, port, kind, abort)`).
  - Route selection and registration happen under the read lock.
  - Updates take the write lock, persist the file, and abort direct tunnels to newly routed (host, port) pairs and routed tunnels whose route disappeared.
  - A 1 s ticker removes expired routes.
- **Admin socket** (minimal HTTP/1.1, one request per connection):
  - `GET /status` → `{version, port, routes:[{host,port,expires_at}], last_error, last_routed:{host,port,at}|null}`.
  - `POST /routes` (body `{host, port, until, proxy}`) → add or replace the route, then return status.
- **Proxy connections** (a task each):
  1. **Read the head** with `httparse` (max 16 KiB, 10 s timeout). Overflow → 431; parse error → 400; origin-form → 400 `asm proxy-router: not a proxy request`. Keep any bytes read past the head.
  2. **Routed CONNECT** (`(host, port)` matches a live route):
     1. Connect to the route's `proxy` (10 s timeout). Send `CONNECT host:port HTTP/1.1\r\nHost: host:port\r\nAsm-Browser-Route: 1\r\n`, plus `Proxy-Authorization: Basic base64(host_id:password)` (always sent; ignored when auth is off), then `\r\n`.
     2. Read the response head:
        - `200` → relay `HTTP/1.1 200 Connection Established`, forward the buffered bytes, register the tunnel, and run `copy_bidirectional`;
        - `403` whose body contains `no active login grant` → drop the route, then relay the response with `Connection: close`;
        - `407` → `502` with body `asm proxy-router: the manager rejected this host's proxy credentials; run asm doctor`;
        - any other status → relay it with `Connection: close`;
        - connect failure → `502` with body `asm proxy-router: cannot reach the asm proxy at <addr>; run asm doctor`.
     3. Every routed error path writes a response before closing. Nothing on a routed path ever goes direct.
     4. Update `last_routed` and log `routed <host>:<port> -> <status>`.
  3. **Other CONNECT.** Dial directly (10 s timeout), reply `200`, forward the buffered bytes, register, and run `copy_bidirectional`. Dial failure → 502 with the OS error.
  4. **Absolute-form `http://`** (used by OpenBot's single-proxy setting; always direct):
     - Only without `Transfer-Encoding` (otherwise 411) and with at most one `Content-Length`.
     - Dial `host:port` (default 80). Send the origin-form request line, the headers minus hop-by-hop ones (`Connection`, `Proxy-Connection`, `Keep-Alive`, `Proxy-Authorization`, `TE`, `Trailer`, `Upgrade`), `Host: <authority>`, `Connection: close`, and exactly `Content-Length` body bytes.
     - Relay the response until the upstream closes.
  5. Allow at most 512 concurrent connections; beyond that, 503.

**`service.rs`** (used only by `browser install`/`uninstall`):
- **`install_service(port)`:**
  - **Executable path:** the first `asm` on `PATH` whose canonical path equals `canonicalize(current_exe())`, else `current_exe()`.
  - **Linux:** requires `systemctl --user show-environment` to succeed; otherwise fail with `no systemd user session; run "asm proxy-router run" under your process supervisor, then re-run with --no-service`. Write `~/.config/systemd/user/asm-proxy-router.service`:
    ```ini
    [Service]
    ExecStart=<exe> proxy-router run --port <port>
    Restart=on-failure
    RestartSec=2

    [Install]
    WantedBy=default.target
    ```
    Add `Environment=XDG_CONFIG_HOME=<value>` when set. Then `systemctl --user daemon-reload && systemctl --user enable --now asm-proxy-router.service`.
  - **macOS:**
    - Write `~/Library/LaunchAgents/com.thinkscape.asm.proxy-router.plist` with `ProgramArguments`, `RunAtLoad`, `KeepAlive`, and `StandardOutPath`/`StandardErrorPath` set to `~/Library/Logs/asm-proxy-router.log`.
    - Run `launchctl bootout gui/<uid>/com.thinkscape.asm.proxy-router` (errors ignored), then `launchctl bootstrap gui/<uid> <plist>`.
- **`remove_service()`:** reverse those steps.
- **Health:** after installing, wait up to 5 s for `/status`. Failure → error, and the browser isn't modified.

### 11. `asm browser install|uninstall|status`
**Wiring.**
- New `crates/asm-cli/src/browser.rs`.
- `main.rs` gets `#[command(subcommand)] Browser(browser::BrowserCommand)` with `Install { target, opts }`, `Uninstall { target, opts }` and `Status { --json }`.
- Targets: `chrome`, `t3code`, `openbot`.
- `asm-cli` adds `rusqlite.workspace = true` (bundled).

**Common to all targets.**
- **Install flow:**
  1. Fetch `/proxy-info`. No `browser_ca_pem` → `the manager does not support browser logins; upgrade it`.
  2. Save the CA as `<config>/browser/ca-<sha8>.crt`.
  3. Unless `--no-service`, install the router service if it isn't installed, and wait for health. Failure → stop before touching the browser.
  4. Record the install in `<config>/browsers.json` (flock'd, keyed by target + location): `{target, key, original (the setting before asm's first install, kept across reinstalls), ca_shas, current_sha, router_port, service, installed_at, version}`.
- **Reinstall** with a different CA sha removes the old rows or anchors first.
- **Uninstall:**
  - Restore `original` only while the current setting still equals what asm wrote; otherwise warn `<setting> was changed after install; left as is`.
  - When the last record is removed, call `remove_service()` and delete `router-routes.json`.
- **Routing:** only `https:`/`wss:` URLs go to the router, never with a direct fallback. The PAC is:
  ```js
  function FindProxyForURL(url, host) {
    if (url.substring(0, 6) == "https:" || url.substring(0, 4) == "wss:") return "PROXY 127.0.0.1:<port>";
    return "DIRECT";
  }
  ```
  It's delivered as a `data:application/x-ns-proxy-autoconfig;base64,…` URL.
- **Existing proxies.** Refuse to install over an existing proxy setup; otherwise the router's direct dials would silently bypass it:
  - **chrome:** the profile `proxy` pref is set and isn't `{"mode":"system"}`; on macOS, `scutil --proxy` shows `HTTPSEnable : 1` or `ProxyAutoConfigEnable : 1`; on Linux, `HTTPS_PROXY`/`https_proxy` is set.
  - **t3code:** `<base>/service.env` sets any `*_PROXY` variable.
  - Error: `this browser already uses a proxy (<what>); asm browser logins can't chain proxies yet`.

**`chrome [--profile NAME] [--user-data-dir DIR]`:**
- **Location:** the user data dir defaults to `~/.config/google-chrome` (Linux) or `~/Library/Application Support/Google/Chrome` (macOS). Other Chromium browsers use `--user-data-dir`.
- **Profile:** matched by directory name or by display name from `Local State` `profile.info_cache.<dir>.name`; default `Default`. If none matches, list the profiles.
- **Running check:** refuse while `<udd>/SingletonLock` → `<hostname>-<pid>` has the same hostname and a live pid: `quit <browser> first (pid N), then re-run`.
- **Version:** `<udd>/Last Version` must be major ≥ 134 (warn if the file is missing).
- **CA row.** In `<profile>/ServerCertificate`:
  - create `meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR)` with version and last_compatible_version = 1 (`INSERT OR IGNORE`);
  - create `certificates(sha256hash_hex TEXT PRIMARY KEY, der_cert BLOB NOT NULL, trust_settings BLOB NOT NULL)`;
  - `INSERT OR REPLACE` (lowercase-hex sha256 of the DER, the DER, `X'0A020803'`).
- **Proxy pref.** In `<profile>/Preferences`, set `proxy = {"mode":"pac_script","pac_url":"<data url>"}`. Write atomically and preserve the file mode.
- **Message:** print `restart <browser> once. HTTPS pages need asm's proxy router; asm doctor checks it.`

**`t3code`:**
- **Locations:** the base is `$T3CODE_HOME` or `~/.t3`. Shells live at `<base>/tools/chrome-headless-shell/<platform>/<version>/chrome-headless-shell`; skip the `asm-real` platform dir.
- **certutil required.** Otherwise fail with `install NSS tools: sudo apt install libnss3-tools (Debian/Ubuntu) or sudo dnf install nss-tools (Fedora)`.
- **Private NSS DB.** `<config>/browser/t3code/pki/nssdb` holds the CA: `certutil -N --empty-password -d sql:<db>`, then `certutil -A -t "C,," -n "asm browser CA <sha8>" -i <ca file> -d sql:<db>`. Also create the symlink `<config>/browser/t3code/home/.pki/nssdb` → that DB.
- **For each unwrapped version:**
  1. Hard-link-copy the version dir to `<base>/tools/chrome-headless-shell/asm-real/<version>/` (`std::fs::hard_link`, falling back to `copy` on `EXDEV`). The path still matches T3's AppArmor glob `/**/tools/chrome-headless-shell/*/*/chrome-headless-shell`, which matters where `kernel.apparmor_restrict_unprivileged_userns = 1` (as on this host).
  2. Atomically replace the original executable with (mode 0755):
     ```sh
     #!/bin/sh
     # asm browser install t3code <asm-version>; real binary: <real>
     export XDG_DATA_HOME='<config>/browser/t3code'
     [ -d "$HOME/.pki/nssdb" ] && export HOME='<config>/browser/t3code/home'
     exec '<base>/tools/chrome-headless-shell/asm-real/<version>/chrome-headless-shell' '--proxy-server=https=127.0.0.1:<port>' "$@"
     ```
- **Message:** record the versions and print `takes effect the next time T3 starts its browser (idle browsers close after 5 minutes; restart T3 to apply now)`.
- **Uninstall:** rename each `asm-real` executable back over its wrapper, then remove `asm-real/<version>` and the private DB.

**`openbot [--trust-user-wide]`:**
- **Confirmation.** Without `--trust-user-wide`, print the following and exit 2: `OpenBot only trusts the OS certificate store. This adds the asm browser CA to your user's trust store; every app using it will trust certificates the asm manager issues (asm issues them only for sites with an active login grant). Re-run with --trust-user-wide to continue.`
- **Linux:**
  - `certutil` is required (same message as above).
  - The DB is `~/.pki/nssdb` if it exists, else `${XDG_DATA_HOME:-~/.local/share}/pki/nssdb`. Create it if there's no `cert9.db`.
  - Then `certutil -A -t "C,," -n "asm browser CA <sha8>" -i <ca file> -d sql:<db>`.
- **macOS:** `security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db <ca file>`.
- **Message:** print `In OpenBot: create a named browser profile, set its proxy to http://127.0.0.1:<router port>, assign it to your agents (shared and agent-only profiles cannot use a proxy). Restart OpenBot.`
- **Uninstall:**
  - Linux: `certutil -D -n "asm browser CA <sha8>" -d sql:<db>`.
  - macOS: `security remove-trusted-cert <file>`, then `security delete-certificate -Z <sha1 hex> ~/Library/Keychains/login.keychain-db`.
  - Either way, for each sha in `ca_shas`.

**`status [--json]`.** For each record print `installed`, `incomplete <reason> — fix: <command>` or `stale CA — fix: asm browser install <target>`:
- **chrome:** the CA row exists and the pref equals asm's PAC.
- **t3code:** every current version is wrapped. If not: `T3 updated its browser to <v> — fix: asm browser install t3code`.
- **openbot:** the cert is present.
- **Router line:** service state, port, `last_routed`, `last_error`.

### 12. `asm doctor`
Extend `proxy.rs` `doctor` (~L256–487). When `browsers.json` has records:
- **Router check:**
  - `ok router … routes:N last_routed:<…>` when it's up.
  - Down → `FAIL proxy router not running — fix: systemctl --user restart asm-proxy-router (logs: journalctl --user -u asm-proxy-router)`. On macOS: `launchctl kickstart -k gui/$UID/com.thinkscape.asm.proxy-router (logs: ~/Library/Logs/asm-proxy-router.log)`. With `--no-service`: `start "asm proxy-router run" under your supervisor`.
  - `last_error` → FAIL with the text.
  - Version mismatch → `warn … fix: asm browser install <target>`.
  - Linux with `Linger=no` → `warn router stops when you log out — fix: loginctl enable-linger $USER`.
- **Browser checks:** the `browser status` lines.

### 13. Login broker (`asm login`)
**Manager** (new `crates/asm-core/src/broker/{mod.rs,cdp.rs,fill.rs}`):
- **`create_login`:**
  - Requires `CAPABILITY_LOGIN_BROKER_V1`.
  - The URL passes `parse_https_url`; its origin is the **export origin**.
  - **Fill origins** = the export origin + `extra_fill_origins` (`https://host[:port]`, at most 5).
  - The secret must be a vault `SecretKind::Login` with a `password` field. With an empty `name`, infer the item exactly as in step 7.
  - Push `Detail::Login(LoginDetail { secret, url, fill_origins, reason })`. `health` adds the capability.
- **FFI:**
  - `RequestDetail::Login { name, vault_name, url, fill_origins, reason, has_totp }`;
  - `Decision::ApproveLogin { duration_secs: Option<u64>, fill_origins: Vec<String> }` (the operator may remove extra origins);
  - `Snapshot.broker_sessions: Vec<BrokerSessionInfo { request_id, url, host_label, started_at, status }>`;
  - `broker_handover(request_id)` and `broker_cancel(request_id)`.
- **On approve:**
  - Keep the request pending for the CLI. Read the password now; read TOTP codes at fill time.
  - Find Chrome on the Mac: `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`, `/Applications/Chromium.app/Contents/MacOS/Chromium`, `/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing`. If none exists, deny with "no Chrome or Chromium on the manager Mac".
  - Profile `<data>/broker/<request_id>` (0700) with `asm-broker.pid`.
  - Launch with `--user-data-dir`, `--remote-debugging-pipe`, `--no-first-run`, `--no-default-browser-check` and `--use-mock-keychain`. Headed, in its own process group, no proxy.
  - At manager start, kill any leftover pid whose process name contains `Chrome`/`Chromium` and delete `<data>/broker/*`.
- **`cdp.rs`:**
  - Pipes on child fds 3 and 4 (`pre_exec` + `libc::dup2`), carrying `\0`-terminated JSON. A reader thread routes replies by `id` and queues events.
  - `call(method, params, session, timeout)`.
  - Startup: `Target.getTargets` → first page → `Target.attachToTarget{flatten:true}` → `Page.enable`, `Runtime.enable`, `DOMStorage.enable` → `Page.navigate{url}`.
- **Fill loop** (every 500 ms until hand-over, cancel, Chrome exit, host revocation (`require_active_host`) or 600 s):
  1. `Page.getFrameTree` → main-frame URL. If its origin isn't an approved fill origin, set status `paused: <origin> is not approved` and fill nothing.
  2. `Page.createIsolatedWorld{frameId, worldName:"asm-fill"}` → `executionContextId`.
  3. `Runtime.evaluate` `FIND_JS` in that context marks one visible, enabled, empty, unfilled input with `data-asm-fill` and returns its kind, by priority:
     - `password` (`input[type=password]`);
     - `username` (`autocomplete~=username|email`, `type=email`, or a name/id matching `/user|email|login/i`);
     - `totp`, if the item has one (`autocomplete=one-time-code`, or a name/id/aria-label matching `/otp|totp|2fa|mfa|one.?time|verification|code/i` with `maxlength<=10` or `inputmode=numeric`).
  4. `Runtime.evaluate("document.querySelector('[data-asm-fill]')", contextId)` → `objectId`.
  5. `Runtime.callFunctionOn{objectId, functionDeclaration: "function(v){this.focus(); this.value=v; this.dispatchEvent(new Event('input',{bubbles:true})); this.dispatchEvent(new Event('change',{bubbles:true})); this.removeAttribute('data-asm-fill'); this.setAttribute('data-asm-filled','')}", arguments:[{value}]}`. The call is bound to that element in that document; after a navigation the object is gone and the call fails. Running in the isolated world means page scripts can't intercept the call itself. TOTP values come from `provider.read` at this moment.
  6. Never submit.
- **Hand-over:**
  1. **Cookies.** `Storage.getCookies`. Keep a host-only cookie (domain without a leading dot) only if its domain equals the export host. Keep a domain cookie (`.d`) only if the export host equals `d` or ends with `.d`. Drop partitioned cookies.
  2. **localStorage.** `DOMStorage.getDOMStorageItems({storageId:{securityOrigin: export origin, isLocalStorage: true}})`.
  3. Build `{cookies:[{name,value,domain,path,expires,httpOnly,secure,sameSite}], origins:[{origin, localStorage}]}`.
  4. `Browser.close` (kill after 5 s), then delete the profile.
  5. Insert a raw lease plus `Done` via `insert_lease_with_request`, as `approve_get` does for raw vault leases: `GetResult{mode: Raw, files:[ResultFile{field:"storage-state", …, substituted: Some(false)}]}`, with expiry from `duration_secs` (default 3600).
- **Failures** deny with "sign-in cancelled", "sign-in timed out after 10 minutes", "the sign-in browser closed before hand-over" or "the requesting host was revoked", then delete the profile.

**Swift:**
- `LoginBrokerApproval` shows the URL, the fill origins (removable), the item, the reason, the line "Exports cookies valid for <host> and <origin>'s localStorage", a duration picker (default 1 h) and Allow/Deny.
- `ApprovalPanel.swift` lists `brokerSessions` with status, "Hand over session" and "Cancel".

**CLI** `asm login <URL> [ITEM] --reason TEXT [--fill-origin ORIGIN]... [--wait SECS (default 900)] [--json]` (new `login.rs`; make `requests::submit` `pub(crate)`):
- Accept only a Raw result with one `storage-state` file. Store it with `SecretsDir::store`, then call `reaper::ensure_running`.
- Print the path, the exported cookie domains, and `load it with your browser tool: omp tab.loadState(<path>), Playwright MCP --storage-state <path>`.

### 14. Agent skill
Add `## Browser logins` to `skill/asm/SKILL.md` after `## Sentinel use outside exec`:
- **Setup:** once per machine where the browser runs, `asm browser install chrome|t3code|openbot --trust-user-wide`, then restart the browser. Run all browser-login `asm` commands on that same machine.
- **Already signed in?** Do nothing.
- **Flow:**
  1. Read the form's submit URL (`document.querySelector('input[type=password]').form.action`).
  2. `asm get --login-url <that URL> --reason "<why>"` (add ITEM if asked).
  3. Open or reload the login page, type the username and the sentinel, submit once.
  4. At an OTP prompt, run `asm get <ITEM>::totp --reason "<why>"` (no popup while the grant lasts) and type the code.
  5. A password field with `maxlength` under 44, or one-box-per-digit OTP inputs → use `asm login`.
- **Errors → action:**

  | Error | Action |
  |---|---|
  | `403 login sentinel not valid for METHOD URL` | Re-request with that URL. |
  | `403 login sentinel must be an entire form or JSON value` | Type the sentinel alone into the password field. |
  | `403 login body must be …` or `one login grant per request` | Use `asm login`. |
  | `403 sentinel expired or revoked` | Already used or ended; request a new grant. |
  | `403 this login grant belongs to another machine` | Request it on the browser's machine. |
  | `503 login secret unavailable` | The vault is locked; tell the operator. |
  | `502 asm proxy-router: …` | `asm doctor`. |
  | Certificate error on the site | `asm browser status`; restart the browser after install. |
  | Every HTTPS page fails | The router is down; run `asm doctor`. |

- **Diagnostics:** `asm doctor`, `asm browser status`, and the logs (`journalctl --user -u asm-proxy-router`, `~/Library/Logs/asm-proxy-router.log`).

## Critical files & anchors
- `third_party/iron-proxy/internal/transform/secrets/secrets.go`: `TransformRequest` (~L366–480), `sentinelInRequest` (~L515), `swapBody` (~L729). Login, scanning, route approval.
- `third_party/iron-proxy/internal/proxy/tunnel.go`: `handleTunnelCONNECT` (~L94), `serveTunnelWithReader`/`serveTunnelTLS` (~L351–400), `handleSOCKS5` (~L141). Auth, tunnel user, browser CA issuance.
- `crates/asm-core/src/manager/requests.rs`: `substitutes` (~L182), `create_get` (~L804), `get_shortcut` (~L875), `approve_get` (~L1510). Grants, inference, totp reuse.
- `crates/asm-core/src/proxy/mod.rs`: `prepare` (~L201), `apply_locked` (~L299–330), `set_config` (~L389). Snapshot, CA, claims dir.
- `crates/asm-cli/src/requests.rs`: `GetArgs` (~L490–526), `get` (~L528–673). The new request shape, barrier and route push.

## Verification
Go commands run from `third_party/iron-proxy`; Rust from the repo root.

0. **Release gate, first (on the Mac).**
   1. Close Chrome. Write the PAC pref into a test profile with a small script mirroring step 11 (or use the step-11 build once it exists).
   2. Start and quit Chrome twice. `chrome://net-internals/#proxy` must still show the PAC.
   3. If the pref is reset, apply the macOS contingency in Assumptions before continuing.
1. **Steps 1–4:** `GOTOOLCHAIN=go1.27.3 go test -race -count=1 ./internal/transform/... ./internal/proxy/... ./internal/certcache/... ./internal/config/...`.
   - **`secrets_test.go`, out-of-scope sentinels:** a body-only sentinel to an unapproved host → 403 not valid; an ended one → 403 ended.
   - **Generic escaping:** the value `p&ss="x\y` becomes `p%26ss%3D%22x%5Cy` in a form body and `p&ss=\"x\\y` in a JSON body.
   - **Login, form body:** `user=a&password=<s>` over TLS to `Target` `/session` → substituted. A second request → 403 ended, and the claim file exists.
   - **Login, JSON body:** `{"user":{"pw":"<s>"}}` → substituted.
   - **Login rejections:**
     - sentinel as a key, inside a longer value, twice, or two grants in one body → 403;
     - `/session?x=1` against `Target` `/session`, or a different path → 403 `login sentinel not valid for POST https://`;
     - plain HTTP → 403;
     - header sentinel → 403 value;
     - multipart, gzip, or a truncated body on the endpoint → 403 body;
     - missing value file → 503;
     - `TunnelUser` ≠ owner → 403 owner;
     - two concurrent requests → exactly one substitution.
   - **`browser_hosts`:** listed and live → `allowed`; unlisted or expired → 403.
   - **`tunnel_test.go`, proxy auth:** CONNECT without or with wrong credentials → 407; right credentials → 200, and inner requests carry `TunnelUser`; SOCKS5 user/pass success and failure; no auth file → unchanged.
   - **`tunnel_test.go`, browser route:**
     - marker `2` → 403;
     - marker `1` with no secrets transform → 403;
     - allowed → the leaf issuer CN is `Agents Secrets Manager Browser CA`;
     - no marker → the root issues the leaf;
     - SNI mismatch → handshake fails;
     - plain HTTP inside → closed;
     - inner `Host` or port mismatch → 421;
     - absolute-form with the marker → 403.
2. **Steps 5–8, 13 (Rust):** `cargo test --workspace` (macOS) or `cargo test --locked -p asm-proto -p asm-cli` (Linux).
   - **Crypto:** `hmac_sha256` against RFC 4231 case 2 (`Jefe` / `what do ya want for nothing?` → `5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843`).
   - **TOTP:** `code_at` against RFC 6238 Appendix B (T=59 and 1111111109; SHA1/256/512; 8 digits). `current_code` at `now = 30k−3` returns the next step's code.
   - **`parse_login_url`:** rejects an IP host, `http://`, `#frag` and non-ASCII. It keeps `?return_to=%2F`, and canonicalizes `https://Example.com:443/a` to `https://example.com/a`.
   - **Render:** `renders_login_entry`, `renders_browser_hosts`, `auth_file`, and the browser CA.
   - **Fixtures and CA:** the Bitwarden totp fixture. `browser_ca::ensure` produces a CA with pathlen 0 and is idempotent.
   - **Requests:**
     - inference with zero, one and two matching items → invalid / ok / invalid listing names;
     - wanted fields = username + password + totp;
     - Raw → Keep; unlimited duration → Keep;
     - `get_shortcut` serves `ITEM::totp` from an active login lease and never serves `password` from it.
   - **e2e (`crates/asm-core/tests/e2e.rs`, after `just proxy`):**
     1. Approve a login grant for host A, `https://login.test/session`.
     2. Raw CONNECT `login.test:443` with `Asm-Browser-Route: 1` to the proxy → 200, and a TLS handshake (root store = browser CA only, SNI `login.test`) succeeds with the browser-CA issuer. `other.test:443` → 403.
     3. Revoke the lease → a new marked CONNECT to `login.test` → 403 within 2 s.
     4. With `require_auth` on: curl without `-U` → 407; with `-U host_id:<proxy_password>` → OK.
3. **Step 10 (router):** new `crates/asm-cli/tests/router.rs`. Start `asm proxy-router run --port <free>` against a fake proxy listener that records CONNECT heads.
   - After `POST /routes {example.test,443,+1h,<fake>}`, CONNECT `example.test:443` → the fake sees `Asm-Browser-Route: 1` and `Proxy-Authorization: Basic base64(h1:<proxy_password>)`, and bytes round-trip.
   - The fake answers 403 `no active login grant` → the client gets 403, and `/status` no longer lists the route.
   - The fake drops the connection → the client gets 502, never a bare close.
   - CONNECT `127.0.0.1:<echo>` → direct.
   - An open direct tunnel to `127.0.0.1:<echo>`, then `POST /routes` for it → the tunnel closes within 1 s.
   - Absolute-form HTTP with `Content-Length` → exactly one request; with chunked → 411. Origin-form → 400.
   - A route with `until` in the past is dropped within 2 s.
   - After a restart, routes reload from `router-routes.json`.
   - The socket mode is 0600.
4. **Step 11 (Chrome, gated):** `ASM_TEST_CHROME=/usr/bin/google-chrome cargo test -p asm-cli browser_install_chrome -- --nocapture`.
   1. Install into a temp user data dir (`Default/Preferences` = `{}`) with `--no-service`, against a fake manager whose `browser_ca_pem` is a test CA.
   2. Assert the CA row exists and the PAC decodes as specified.
   3. Start a fake router on 7418 that forwards CONNECTs to a rustls server with a test-CA leaf for `example.test`. Run `chrome --headless=new --host-resolver-rules="MAP example.test:443 127.0.0.1:<p>" --dump-dom https://example.test/` → `TRUST-OK`, and the fake router saw the CONNECT.
   4. `http://` goes direct (the fake router sees nothing). A `[self-signed, testCA]` chain → not loaded.
   5. Reinstall, then uninstall → `proxy` is removed.
   6. Also open `wss://example.test/` from a page, to observe whether Chrome sends `wss` through the PAC's `wss:` branch. If it doesn't, apply the wss contingency.
   7. `just cli` must build (bundled rusqlite on musl).
5. **Manual, this Linux host** (T3 nightly; userns restricted; certutil installed). Use the Vaultwarden item `herokuapp` (`tomsmith` / `SuperSecretPassword!`, URI `https://the-internet.herokuapp.com/login`).
   1. `asm browser install t3code` → systemd user service active; `asm doctor` → `ok router`.
   2. In a T3 thread on this host:
      1. `asm get --login-url https://the-internet.herokuapp.com/authenticate --reason test` → the item is inferred, there's one approval, and the username, the sentinel and (if a key exists) a totp file are printed.
      2. `preview_open` the login page, type both values and submit.
      3. "You logged into a secure area!" appears, and `asm browser status` shows `last_routed the-internet.herokuapp.com:443`. This proves the AppArmor profile still attaches.
      4. A second submit → `sentinel expired or revoked`.
   3. `asm browser install chrome` (Chrome closed), then start Chrome:
      1. The same login works via chrome-devtools-mcp `--autoConnect` or the omp relay.
      2. `systemctl --user stop asm-proxy-router` → HTTPS pages fail and HTTP pages load. Start the router → HTTPS works within 5 s.
6. **Manual, on the Mac:**
   1. `asm browser install chrome --profile Default`, then the herokuapp login via the Codex desktop Chrome extension.
   2. `asm browser install openbot --trust-user-wide` → keychain prompt → configure the named profile → log in via OpenBot.
   3. `asm login https://the-internet.herokuapp.com/login --reason 'broker test'` → approve → the Chrome window is filled → click Login → Hand over. The storage-state contains only `the-internet.herokuapp.com` cookies. Playwright `newContext({storageState})` opens `/secure` signed in.
7. **TOTP (manual):** with an authenticator key on the test item, the login grant's totp file matches the Bitwarden app. `asm get Vaultwarden/herokuapp::totp --reason otp` 30 s later → no popup and a new code.

## Assumptions & contingencies
- **The browser CA is signer-scoped.** It's installed once and trusted for any name. iron-proxy issues leaves from it only for marked, pipeline-approved CONNECTs to active grant (host, port) pairs with a matching SNI. Stealing `browser-ca.key` from the Mac would allow impersonating any site to installed browsers, the same risk class as the existing root key. For OpenBot this trust is user-wide and opt-in.
- **Sentinel model.** With proxy authentication off (the default), an unused login sentinel is a bearer capability. Anyone who learns it and can reach the proxy could redeem it first and get that site's session, though not the password. This is the same as exec sentinels. With proxy authentication on, only the requesting machine can redeem it.
- **Mac-local agents.** For an agent on the manager Mac (Codex desktop driving the Mac's Chrome), the guarantee is "the password never reaches the model". Same-user processes on the Mac can read vault data anyway (`README.md` security model).
- **Co-location.** Grants are requested on the browser's machine. The router there is the only one that knows the route.
- **HTTPS without fallback.** HTTPS for asm-configured browsers needs the router; HTTP stays direct. Routing for a grant lasts from approval to expiry (max 1 h, default 15 min), including after the single use.
- **Echo exposure.** The sentinel may be any whole form or JSON value at the exact endpoint. A site that echoes the field holding the sentinel (for example a username on an error page) can return the password to the page. Response redaction is best effort and never covers values shorter than 8 bytes.
- **Proxy authentication is opt-in** (default off), so the manager can still be upgraded before the CLIs.
- **TOTP.** A login grant includes the current code, and plain `ITEM::totp` requests reuse the grant without a popup until it ends. Steam and HOTP keys are unsupported. A custom field named `totp` is reserved.
- **macOS Chrome resets the hand-written `proxy` pref** (gate 0 fails): on macOS, the `chrome` target writes a plist with `ProxySettings {ProxyMode: pac_script, ProxyPacUrl: <data url>}` and `AsmManaged`.
  - It refuses to overwrite an existing non-asm file.
  - It prints `sudo cp … "/Library/Managed Preferences/$USER/com.google.Chrome.plist"`.
  - It keeps the per-profile CA row, and says the policy applies to every profile of that Chrome.
- **Chrome doesn't send `wss:` through the PAC's `wss:` branch** (step 4.6): keep the PAC unchanged and accept that WebSocket connections to a granted site go direct. Login substitution never uses WebSockets. Add one line to the skill's error table: "a site whose live updates break only while a login grant is active → its WebSocket egress differs from its HTTPS egress; sign in with `asm login` instead".
- **T3 rejects or replaces the wrapper, or tabs fail with a sandbox/userns error:** `asm browser uninstall t3code` and mark the target unsupported on that host (`T3's browser sandbox rejects the wrapper; needs an upstream T3 proxy/CA setting`). Never disable T3's sandbox.
- **`just cli` fails to build bundled SQLite for musl:** set `CC_<target>`/`AR_<target>` to cargo-zigbuild's `zig cc` in the `cli` recipe.
- **DBSC- or IP-bound sessions** may log out after a broker hand-over or after the routing window ends; report the affected sites.
