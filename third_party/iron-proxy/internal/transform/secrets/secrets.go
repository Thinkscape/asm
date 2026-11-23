// Package secrets implements a transform that swaps proxy tokens for real
// secrets on outbound requests, scoped to allowed hosts.
package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/headers"
	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("secrets", factory)
}

// secretsConfig is the YAML config structure.
type secretsConfig struct {
	Secrets []secretEntry `yaml:"secrets"`
	// BrowserHosts lists the (host, port) pairs a marked browser CONNECT
	// (Asm-Browser-Route: 1) may be routed to, each until a Unix time.
	BrowserHosts []browserHostConfig `yaml:"browser_hosts"`
}

type browserHostConfig struct {
	Host  string `yaml:"host"`
	Port  int    `yaml:"port"`
	Until int64  `yaml:"until"`
}

type secretEntry struct {
	Source  yaml.Node              `yaml:"source"`
	Rules   []hostmatch.RuleConfig `yaml:"rules"`
	Inject  *injectConfig          `yaml:"inject,omitempty"`
	Replace *replaceConfig         `yaml:"replace,omitempty"`

	// Deprecated top-level fields for backwards compatibility.
	// Users should migrate to the replace block.
	ProxyValue   string   `yaml:"proxy_value,omitempty"`
	MatchHeaders []string `yaml:"match_headers,omitempty"`
	MatchBody    bool     `yaml:"match_body,omitempty"`
	Require      bool     `yaml:"require,omitempty"`
}

type replaceConfig struct {
	ProxyValue   string   `yaml:"proxy_value"`
	MatchHeaders []string `yaml:"match_headers,omitempty"`
	MatchBody    bool     `yaml:"match_body,omitempty"`
	MatchPath    bool     `yaml:"match_path,omitempty"`
	MatchQuery   bool     `yaml:"match_query,omitempty"`
	Require      bool     `yaml:"require,omitempty"`
	// AllowPlainHTTP permits substitution on requests that did not arrive
	// over TLS. Off by default: a real value sent over plain HTTP is visible
	// on the network path to the upstream.
	AllowPlainHTTP bool `yaml:"allow_plain_http,omitempty"`
	// Ended marks the sentinel of a lease that has expired or been revoked.
	// The entry never substitutes and takes no source or rules; a request
	// carrying its proxy_value in a header, the path or the query is
	// rejected with 403.
	Ended bool `yaml:"ended,omitempty"`
	// Login makes the entry a login entry: its sentinel is substituted only
	// as an entire form or JSON value of one HTTPS request to the exact form
	// action, once.
	Login *loginConfig `yaml:"login,omitempty"`
}

type loginConfig struct {
	Port int `yaml:"port"`
	// Target is the escaped path plus "?query" when present.
	Target string `yaml:"target"`
	// Owner is the paired host ID allowed to redeem the sentinel when proxy
	// authentication is on.
	Owner string `yaml:"owner"`
	// ClaimFile is created exclusively on first use; its existence ends the
	// sentinel.
	ClaimFile string `yaml:"claim_file"`
}

type injectConfig struct {
	Header     string `yaml:"header,omitempty"`
	QueryParam string `yaml:"query_param,omitempty"`
	Formatter  string `yaml:"formatter,omitempty"`
	// Require rejects the request when the secret is unavailable. When
	// false (default), an unavailable secret is skipped silently.
	Require bool `yaml:"require,omitempty"`
}

// resolvedSecret is a secret ready for use after config parsing and source resolution.
type resolvedSecret struct {
	source secretSource
	mode   string // "replace" or "inject"
	rules  []hostmatch.Rule

	// replace mode fields
	proxyValue     string
	matchHeaders   []headerMatcher // empty = all headers
	matchBody      bool
	matchPath      bool
	matchQuery     bool
	require        bool
	allowPlainHTTP bool
	login          *loginConfig // non-nil for login entries

	// inject mode fields
	injectHeader     string
	injectQueryParam string
	formatter        *template.Template // nil = identity (raw value)
}

// headerMatcher selects request headers to scan. Exactly one of name or re is set.
type headerMatcher struct {
	name     string         // canonical header name; "" if regex
	wireName string         // header name with the user's original casing; "" if regex
	re       *regexp.Regexp // nil if literal name match
}

// parseHeaderMatchers compiles match_headers entries. Patterns delimited by
// "/.../" are compiled as case-insensitive regular expressions matched against
// canonical header names; all other entries are literal header names. Literal
// names are matched case-insensitively (via canonicalization) but the user's
// original casing is preserved when writing the header back over the wire.
func parseHeaderMatchers(patterns []string, ctx string) ([]headerMatcher, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	matchers := make([]headerMatcher, 0, len(patterns))
	for _, p := range patterns {
		if len(p) >= 2 && strings.HasPrefix(p, "/") && strings.HasSuffix(p, "/") {
			re, err := regexp.Compile("(?i)" + p[1:len(p)-1])
			if err != nil {
				return nil, fmt.Errorf("%s: invalid match_headers regex %q: %w", ctx, p, err)
			}
			matchers = append(matchers, headerMatcher{re: re})
			continue
		}
		matchers = append(matchers, headerMatcher{name: http.CanonicalHeaderKey(p), wireName: p})
	}
	return matchers, nil
}

// formatterData is the template context for inject formatters.
type formatterData struct {
	Value string
}

var formatterFuncs = template.FuncMap{
	"base64": func(parts ...string) string {
		return base64.StdEncoding.EncodeToString([]byte(strings.Join(parts, "")))
	},
}

// Secrets is the transform that swaps proxy tokens for real secrets.
type Secrets struct {
	secrets []resolvedSecret
	// ended holds the proxy values of ended entries; they never substitute
	// and are not redaction needles.
	ended []string
	// hasReplace is true when at least one entry is in replace mode
	// (login entries included).
	hasReplace bool
	// hasLogin is true when at least one entry is a login entry.
	hasLogin bool
	// browserHosts are the (host, port) pairs a marked browser CONNECT may
	// be routed to.
	browserHosts []browserHostConfig
}

const (
	msgSentinelNotValid = "asm: sentinel not valid for this host or scheme"
	msgSentinelEnded    = "asm: sentinel expired or revoked; run asm get again"
	msgWebSocketSwap    = "asm: sentinels are not substituted on WebSocket upgrades"
	msgBodyUnreadable   = "asm: request body could not be read"

	msgLoginRequest     = "asm: login sentinel not valid for %s %s"
	msgLoginValue       = "asm: login sentinel must be an entire form or JSON value, sent once"
	msgLoginBody        = "asm: login body must be application/x-www-form-urlencoded or JSON without Content-Encoding"
	msgLoginMulti       = "asm: one login grant per request"
	msgLoginUnavailable = "asm: login secret unavailable"
	msgLoginOwner       = "asm: this login grant belongs to another machine"

	msgBrowserRoute = "asm: no active login grant routes this host through asm"
)

// browserRouteHeader marks a CONNECT from an asm proxy router for a browser.
const browserRouteHeader = "Asm-Browser-Route"

func factory(cfg yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c secretsConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing secrets config: %w", err)
	}
	return newFromConfig(c, defaultRegistry(logger))
}

// defaultRegistry returns the standard set of secret source builders. It is
// used by both the secrets transform's factory and by BuildSource so other
// transforms can compose the same sources.
func defaultRegistry(logger *slog.Logger) sourceBuilderRegistry {
	return sourceBuilderRegistry{
		"env":               newEnvBuilder(logger),
		"file":              newFileBuilder(logger),
		"control_plane":     newControlPlaneBuilder(logger),
		"aws_sm":            newAWSSMBuilder(logger),
		"aws_ssm":           newAWSSSMBuilder(logger),
		"vault_kv":          newVaultKVBuilder(logger),
		"1password":         newOPBuilder(logger),
		"1password_connect": newOPConnectBuilder(logger),
	}
}

// BuildSource constructs a secret Source from a yaml node shaped like a
// top-level "source:" block (e.g. {type: env, var: FOO}). It is intended for
// other transforms that want to load their inputs from any registered
// secrets backend (1Password, AWS SM, etc.).
func BuildSource(node yaml.Node, logger *slog.Logger) (Source, error) {
	return resolveSource(defaultRegistry(logger), node)
}

// jsonKeyHint peeks at the optional json_key field, common to every source
// type. When set, the source's value is parsed as a JSON object and the
// single top-level string field at that key is extracted.
type jsonKeyHint struct {
	JSONKey string `yaml:"json_key"`
}

// resolveSource dispatches a source config through the registry and applies
// the optional json_key extraction, which is available to every source type.
func resolveSource(registry sourceBuilderRegistry, node yaml.Node) (secretSource, error) {
	var hint sourceTypeHint
	if err := node.Decode(&hint); err != nil {
		return nil, fmt.Errorf("parsing source type: %w", err)
	}
	if hint.Type == "" {
		return nil, fmt.Errorf("source.type is required")
	}
	builder, ok := registry[hint.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported source type %q", hint.Type)
	}
	src, err := builder.Build(node)
	if err != nil {
		return nil, err
	}
	var jk jsonKeyHint
	if err := node.Decode(&jk); err != nil {
		return nil, fmt.Errorf("parsing json_key: %w", err)
	}
	if jk.JSONKey != "" {
		src = &jsonKeySource{inner: src, key: jk.JSONKey}
	}
	return src, nil
}

// newFromConfig creates a Secrets transform from a parsed config.
func newFromConfig(cfg secretsConfig, registry sourceBuilderRegistry) (*Secrets, error) {
	resolved := make([]resolvedSecret, 0, len(cfg.Secrets))
	var ended []string
	hasReplace := false
	hasLogin := false

	if err := validateBrowserHosts(cfg.BrowserHosts); err != nil {
		return nil, err
	}

	for i, entry := range cfg.Secrets {
		// Normalize legacy top-level fields into a replace block.
		replace, inject, err := normalizeEntry(i, &entry)
		if err != nil {
			return nil, err
		}

		if replace != nil && replace.Login != nil {
			if err := validateLogin(i, &entry, replace); err != nil {
				return nil, err
			}
			hasLogin = true
		}

		if replace != nil && replace.Ended {
			if !entry.Source.IsZero() || len(entry.Rules) > 0 {
				return nil, fmt.Errorf("secrets[%d]: an ended entry takes no source or rules", i)
			}
			ended = append(ended, replace.ProxyValue)
			continue
		}

		source, err := resolveSource(registry, entry.Source)
		if err != nil {
			return nil, fmt.Errorf("secrets[%d]: %w", i, err)
		}

		rules, err := hostmatch.CompileRules(entry.Rules, fmt.Sprintf("secrets[%d]", i))
		if err != nil {
			return nil, err
		}

		if inject != nil {
			sec := resolvedSecret{
				source:           source,
				mode:             "inject",
				rules:            rules,
				require:          inject.Require,
				injectHeader:     inject.Header,
				injectQueryParam: inject.QueryParam,
			}
			if inject.Formatter != "" {
				tmpl, err := template.New(fmt.Sprintf("secrets[%d]", i)).Funcs(formatterFuncs).Parse(inject.Formatter)
				if err != nil {
					return nil, fmt.Errorf("secrets[%d]: parsing formatter template: %w", i, err)
				}
				sec.formatter = tmpl
			}
			resolved = append(resolved, sec)
		} else {
			matchers, err := parseHeaderMatchers(replace.MatchHeaders, fmt.Sprintf("secrets[%d]", i))
			if err != nil {
				return nil, err
			}
			hasReplace = true
			resolved = append(resolved, resolvedSecret{
				source:         source,
				mode:           "replace",
				proxyValue:     replace.ProxyValue,
				matchHeaders:   matchers,
				matchBody:      replace.MatchBody,
				matchPath:      replace.MatchPath,
				matchQuery:     replace.MatchQuery,
				require:        replace.Require,
				allowPlainHTTP: replace.AllowPlainHTTP,
				rules:          rules,
				login:          replace.Login,
			})
		}
	}

	return &Secrets{
		secrets:      resolved,
		ended:        ended,
		hasReplace:   hasReplace,
		hasLogin:     hasLogin,
		browserHosts: cfg.BrowserHosts,
	}, nil
}

// validateLogin checks a login entry: only proxy_value, login and rules may
// be set, the login block is complete, and the rules name exactly one host
// for the form-submission methods.
func validateLogin(i int, entry *secretEntry, replace *replaceConfig) error {
	if len(replace.MatchHeaders) > 0 || replace.MatchBody || replace.MatchPath || replace.MatchQuery ||
		replace.Require || replace.AllowPlainHTTP || replace.Ended {
		return fmt.Errorf("secrets[%d]: login entries take only proxy_value, login and rules", i)
	}
	login := replace.Login
	if login.Port < 1 || login.Port > 65535 {
		return fmt.Errorf("secrets[%d]: login.port must be 1-65535", i)
	}
	if !strings.HasPrefix(login.Target, "/") {
		return fmt.Errorf("secrets[%d]: login.target must start with /", i)
	}
	if login.Owner == "" {
		return fmt.Errorf("secrets[%d]: login.owner is required", i)
	}
	if !filepath.IsAbs(login.ClaimFile) {
		return fmt.Errorf("secrets[%d]: login.claim_file must be an absolute path", i)
	}
	if !loginRuleShape(entry.Rules) {
		return fmt.Errorf("secrets[%d]: login entries take exactly one rule with one literal host, no cidr or paths, and methods POST, PUT, PATCH", i)
	}
	return nil
}

// loginRuleShape reports whether rules is one rule for a literal host (no
// glob characters), with no cidr or paths, for exactly the methods POST,
// PUT and PATCH.
func loginRuleShape(rules []hostmatch.RuleConfig) bool {
	if len(rules) != 1 {
		return false
	}
	r := rules[0]
	if r.Host == "" || strings.ContainsAny(r.Host, `*?[]\`) || r.CIDR != "" || len(r.Paths) > 0 || len(r.Methods) != 3 {
		return false
	}
	seen := map[string]bool{}
	for _, m := range r.Methods {
		m = strings.ToUpper(m)
		if (m != http.MethodPost && m != http.MethodPut && m != http.MethodPatch) || seen[m] {
			return false
		}
		seen[m] = true
	}
	return true
}

// validateBrowserHosts checks each browser_hosts entry: a lowercase host, a
// port in 1-65535 and a positive until.
func validateBrowserHosts(hosts []browserHostConfig) error {
	for i, h := range hosts {
		if h.Host == "" || h.Host != strings.ToLower(h.Host) {
			return fmt.Errorf("browser_hosts[%d]: host must be non-empty and lowercase", i)
		}
		if h.Port < 1 || h.Port > 65535 {
			return fmt.Errorf("browser_hosts[%d]: port must be 1-65535", i)
		}
		if h.Until <= 0 {
			return fmt.Errorf("browser_hosts[%d]: until must be positive", i)
		}
	}
	return nil
}

// normalizeEntry validates the entry and returns either a replaceConfig or injectConfig.
// It handles legacy top-level fields by normalizing them into a replaceConfig.
func normalizeEntry(i int, entry *secretEntry) (*replaceConfig, *injectConfig, error) {
	hasLegacy := entry.ProxyValue != "" || len(entry.MatchHeaders) > 0 || entry.MatchBody || entry.Require
	hasReplace := entry.Replace != nil
	hasInject := entry.Inject != nil

	// Count how many modes are specified.
	modeCount := 0
	if hasLegacy {
		modeCount++
	}
	if hasReplace {
		modeCount++
	}
	if hasInject {
		modeCount++
	}

	if modeCount == 0 {
		return nil, nil, fmt.Errorf("secrets[%d]: must specify either inject or replace", i)
	}
	if modeCount > 1 {
		if hasLegacy && hasReplace {
			return nil, nil, fmt.Errorf("secrets[%d]: cannot use both top-level proxy_value/match_headers and replace block", i)
		}
		if hasLegacy && hasInject {
			return nil, nil, fmt.Errorf("secrets[%d]: cannot use both top-level proxy_value/match_headers and inject block", i)
		}
		return nil, nil, fmt.Errorf("secrets[%d]: cannot specify both inject and replace", i)
	}

	if hasInject {
		if err := validateInject(i, entry.Inject); err != nil {
			return nil, nil, err
		}
		return nil, entry.Inject, nil
	}

	if hasReplace {
		if entry.Replace.ProxyValue == "" {
			return nil, nil, fmt.Errorf("secrets[%d]: replace.proxy_value is required", i)
		}
		return entry.Replace, nil, nil
	}

	// Legacy top-level fields: normalize into replaceConfig.
	if entry.ProxyValue == "" {
		return nil, nil, fmt.Errorf("secrets[%d]: proxy_value is required", i)
	}
	return &replaceConfig{
		ProxyValue:   entry.ProxyValue,
		MatchHeaders: entry.MatchHeaders,
		MatchBody:    entry.MatchBody,
		Require:      entry.Require,
	}, nil, nil
}

func validateInject(i int, cfg *injectConfig) error {
	hasHeader := cfg.Header != ""
	hasQuery := cfg.QueryParam != ""

	if !hasHeader && !hasQuery {
		return fmt.Errorf("secrets[%d]: inject must specify either header or query_param", i)
	}
	if hasHeader && hasQuery {
		return fmt.Errorf("secrets[%d]: inject cannot specify both header and query_param", i)
	}
	return nil
}

func (s *Secrets) Name() string { return "secrets" }

// secretRecord is the audit record of one entry's substitutions.
type secretRecord struct {
	Secret    string   `json:"secret"`
	Locations []string `json:"locations"`
}

func (s *Secrets) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	// A marked browser CONNECT is approved only for a live browser_hosts
	// pair; the proxy issues browser-CA leaves only for approved tunnels.
	if req.Method == http.MethodConnect && req.Header.Get(browserRouteHeader) == "1" {
		if !s.browserRouteAllowed(req, time.Now().Unix()) {
			tctx.Annotate("reject_reason", "browser_route")
			return rejectResult(req, http.StatusForbidden, msgBrowserRoute), nil
		}
		tctx.Annotate("browser_route", "allowed")
	}

	var swapped, injected []secretRecord
	var unavailable []string

	if s.hasReplace {
		// Let the upstream transport negotiate gzip and decode it itself, so
		// TransformResponse sees an identity-encoded body it can redact.
		// Upstream headers are copied from req after request transforms.
		req.Header.Del("Accept-Encoding")
	}

	var body []byte
	bodyOK := false
	if s.hasReplace || len(s.ended) > 0 {
		var err error
		body, bodyOK, err = scannableBody(req)
		if err != nil {
			tctx.Annotate("reject_reason", "body_unreadable")
			return rejectResult(req, http.StatusBadRequest, msgBodyUnreadable), nil
		}
	}

	// An ended sentinel reaches no destination, whatever else the request
	// carries; the client learns to request a new lease.
	for _, pv := range s.ended {
		if sentinelInRequest(req, pv, body) {
			tctx.Annotate("reject_reason", "sentinel_ended")
			return rejectResult(req, http.StatusForbidden, msgSentinelEnded), nil
		}
	}

	// The login substitution is validated here and committed (claimed) only
	// after every other check below has passed, so a request rejected for
	// another reason never consumes the grant.
	var login *pendingLogin
	if s.hasLogin {
		var res *transform.TransformResult
		login, res = s.checkLogin(ctx, tctx, req, body, bodyOK)
		if res != nil {
			return res, nil
		}
	}

	for _, sec := range s.secrets {
		if sec.login != nil {
			// Login entries are handled by checkLogin/commitLogin only.
			continue
		}
		hostMatch := hostmatch.MatchAnyRule(sec.rules, req)
		if sec.mode == "replace" && (!hostMatch || (req.TLS == nil && !sec.allowPlainHTTP)) {
			// A sentinel headed somewhere it is not substituted would leak
			// the placeholder (a bearer capability) to that destination.
			if sentinelInRequest(req, sec.proxyValue, body) {
				tctx.Annotate("rejected", sec.source.Name())
				tctx.Annotate("reject_reason", "sentinel_not_valid")
				return rejectResult(req, http.StatusForbidden, msgSentinelNotValid), nil
			}
			continue
		}
		if !hostMatch {
			continue
		}

		name := sec.source.Name()
		realValue, err := sec.source.Get(ctx)
		if err != nil {
			if sec.require {
				tctx.Annotate("rejected", name)
				tctx.Annotate("reject_reason", "secret_unavailable")
				return &transform.TransformResult{Action: transform.ActionReject}, nil
			}
			unavailable = append(unavailable, name)
			continue
		}

		if sec.mode == "inject" {
			locations, err := s.injectSecret(req, &sec, realValue)
			if err != nil {
				return nil, fmt.Errorf("injecting secret %q: %w", name, err)
			}
			if len(locations) > 0 {
				injected = append(injected, secretRecord{Secret: name, Locations: locations})
			}
			continue
		}

		var locations []string
		locations = append(locations, s.swapHeaders(tctx, req, &sec, realValue)...)

		if sec.matchQuery {
			locations = append(locations, s.swapQuery(req, &sec, realValue)...)
		}

		if sec.matchPath {
			if loc := s.swapPath(req, &sec, realValue); loc != "" {
				locations = append(locations, loc)
			}
		}

		if sec.matchBody {
			if loc := s.swapBody(req, &sec, realValue); loc != "" {
				locations = append(locations, loc)
			}
		}

		if len(locations) > 0 {
			swapped = append(swapped, secretRecord{Secret: name, Locations: locations})
			addRedactPair(tctx, realValue, sec.proxyValue)
			// A partial response could split an echoed value so response
			// redaction cannot see it whole.
			req.Header.Del("Range")
			req.Header.Del("If-Range")
		} else if sec.require {
			tctx.Annotate("rejected", name)
			return &transform.TransformResult{Action: transform.ActionReject}, nil
		}
	}

	// WebSocket frames are relayed raw and cannot be redacted, so a
	// substituted upgrade request would hand the real value to a channel
	// with no response protection.
	if (len(swapped) > 0 || login != nil) && isWebSocketUpgrade(req) {
		tctx.Annotate("reject_reason", "websocket_upgrade")
		return rejectResult(req, http.StatusForbidden, msgWebSocketSwap), nil
	}

	if login != nil {
		record, res := commitLogin(tctx, req, login)
		if res != nil {
			return res, nil
		}
		swapped = append(swapped, *record)
	}

	if len(swapped) > 0 {
		tctx.Annotate("swapped", swapped)
	}
	if len(injected) > 0 {
		tctx.Annotate("injected", injected)
	}
	if len(unavailable) > 0 {
		tctx.Annotate("secret_unavailable", unavailable)
	}

	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// pendingLogin is a validated login substitution awaiting its claim.
type pendingLogin struct {
	sec      *resolvedSecret
	kind     bodyKind
	real     string
	origBody io.ReadCloser // req.Body when the substitution was computed
	replaced []byte
}

// checkLogin runs the validation half of the login phase: it finds the one
// login entry whose sentinel the request carries and checks that the
// request is an HTTPS submission to the entry's exact form action with the
// sentinel as one whole body value. It returns the substitution to commit,
// or a reject result. Nothing is claimed or changed on the request.
func (s *Secrets) checkLogin(ctx context.Context, tctx *transform.TransformContext, req *http.Request, body []byte, bodyOK bool) (*pendingLogin, *transform.TransformResult) {
	var hit *resolvedSecret
	hits := 0
	for i := range s.secrets {
		sec := &s.secrets[i]
		if sec.login != nil && sentinelInRequest(req, sec.proxyValue, body) {
			hit = sec
			hits++
		}
	}
	if hits > 1 {
		tctx.Annotate("reject_reason", "login_multi")
		return nil, rejectResult(req, http.StatusForbidden, msgLoginMulti)
	}

	// A body the proxy cannot scan could hide a sentinel, so the login
	// endpoint takes only identity-encoded form or JSON bodies.
	kind := requestBodyKind(req)
	loginBody := bodyOK && (kind == bodyForm || kind == bodyJSON)
	if !loginBody {
		for i := range s.secrets {
			sec := &s.secrets[i]
			if sec.login != nil && sec != hit && loginEndpointMatch(req, sec) {
				tctx.Annotate("rejected", sec.source.Name())
				tctx.Annotate("reject_reason", "login_body")
				return nil, rejectResult(req, http.StatusForbidden, msgLoginBody)
			}
		}
	}
	if hit == nil {
		return nil, nil
	}

	name := hit.source.Name()
	reject := func(status int, reason, msg string) (*pendingLogin, *transform.TransformResult) {
		tctx.Annotate("rejected", name)
		tctx.Annotate("reject_reason", reason)
		return nil, rejectResult(req, status, msg)
	}
	if !loginEndpointMatch(req, hit) {
		return reject(http.StatusForbidden, "login_scope", fmt.Sprintf(msgLoginRequest, req.Method, requestURL(req)))
	}
	if sentinelInRequest(req, hit.proxyValue, nil) {
		return reject(http.StatusForbidden, "login_value", msgLoginValue)
	}
	if !loginBody {
		return reject(http.StatusForbidden, "login_body", msgLoginBody)
	}
	// With proxy authentication off the sentinel is a bearer capability,
	// like exec sentinels.
	if tctx.TunnelUser != "" && tctx.TunnelUser != hit.login.Owner {
		return reject(http.StatusForbidden, "login_owner", msgLoginOwner)
	}
	realValue, err := hit.source.Get(ctx)
	if err != nil {
		return reject(http.StatusServiceUnavailable, "secret_unavailable", msgLoginUnavailable)
	}
	replaced, ok := swapLogin(kind, body, hit.proxyValue, realValue)
	if !ok {
		return reject(http.StatusForbidden, "login_value", msgLoginValue)
	}
	return &pendingLogin{sec: hit, kind: kind, real: realValue, origBody: req.Body, replaced: replaced}, nil
}

// commitLogin claims a validated login substitution and installs it. It
// runs after every other check of the request has passed. The claim
// precedes forwarding, so an indeterminate upstream outcome still consumes
// the grant.
func commitLogin(tctx *transform.TransformContext, req *http.Request, p *pendingLogin) (*secretRecord, *transform.TransformResult) {
	name := p.sec.source.Name()
	reject := func(reason, msg string) (*secretRecord, *transform.TransformResult) {
		tctx.Annotate("rejected", name)
		tctx.Annotate("reject_reason", reason)
		return nil, rejectResult(req, http.StatusForbidden, msg)
	}

	replaced := p.replaced
	if req.Body != p.origBody {
		// A match_body entry rewrote the body after validation; substitute
		// into the current body so its swap is kept.
		current, ok, err := scannableBody(req)
		if err != nil || !ok {
			return reject("login_body", msgLoginBody)
		}
		if replaced, ok = swapLogin(p.kind, current, p.sec.proxyValue, p.real); !ok {
			return reject("login_value", msgLoginValue)
		}
	}

	if err := claimLogin(p.sec.login.ClaimFile, time.Now()); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			tctx.Annotate("claim_error", err.Error())
		}
		return reject("sentinel_ended", msgSentinelEnded)
	}

	req.Body = transform.NewBufferedBodyFromBytes(replaced)
	addRedactPair(tctx, p.real, p.sec.proxyValue)
	// A partial response could split an echoed value so response redaction
	// cannot see it whole.
	req.Header.Del("Range")
	req.Header.Del("If-Range")
	return &secretRecord{Secret: name, Locations: []string{"body"}}, nil
}

// swapLogin substitutes a login sentinel in a form or JSON body.
func swapLogin(kind bodyKind, body []byte, sentinel, real string) ([]byte, bool) {
	if kind == bodyForm {
		return swapLoginForm(body, sentinel, real)
	}
	return swapLoginJSON(body, sentinel, real)
}

// loginEndpointMatch reports whether req is an HTTPS request to the login
// entry's host, method, port and exact escaped request target.
func loginEndpointMatch(req *http.Request, sec *resolvedSecret) bool {
	return req.TLS != nil &&
		hostmatch.MatchAnyRule(sec.rules, req) &&
		effectivePort(req) == strconv.Itoa(sec.login.Port) &&
		requestTarget(req) == sec.login.Target
}

// effectivePort is the port in req.Host, else the scheme's default.
func effectivePort(req *http.Request) string {
	if _, port, err := net.SplitHostPort(req.Host); err == nil && port != "" {
		return port
	}
	if req.TLS != nil {
		return "443"
	}
	return "80"
}

// requestTarget is the escaped path plus "?query" when the request has one.
func requestTarget(req *http.Request) string {
	target := req.URL.EscapedPath()
	if req.URL.RawQuery != "" || req.URL.ForceQuery {
		target += "?" + req.URL.RawQuery
	}
	return target
}

// requestURL renders the request as scheme://host:port/target for messages.
func requestURL(req *http.Request) string {
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}
	host := strings.ToLower(hostmatch.StripPort(req.Host))
	return scheme + "://" + net.JoinHostPort(host, effectivePort(req)) + requestTarget(req)
}

// claimLogin creates path exclusively and makes it durable, recording the
// time of use. An existing file means the sentinel was already used.
func claimLogin(path string, now time.Time) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.WriteString(now.UTC().Format(time.RFC3339))
	syncErr := f.Sync()
	if err := errors.Join(writeErr, syncErr, f.Close()); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	syncErr = dir.Sync()
	return errors.Join(syncErr, dir.Close())
}

// browserRouteAllowed reports whether the CONNECT target is a browser_hosts
// pair whose until lies after now (Unix seconds).
func (s *Secrets) browserRouteAllowed(req *http.Request, now int64) bool {
	host, portStr, err := net.SplitHostPort(req.Host)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	host = strings.ToLower(host)
	for _, bh := range s.browserHosts {
		if bh.Host == host && bh.Port == port && now < bh.Until {
			return true
		}
	}
	return false
}

func (s *Secrets) injectSecret(req *http.Request, sec *resolvedSecret, realValue string) ([]string, error) {
	formatted, err := s.formatValue(sec, realValue)
	if err != nil {
		return nil, err
	}

	var locations []string
	if sec.injectHeader != "" {
		headers.Set(req.Header, sec.injectHeader, formatted)
		locations = append(locations, "header:"+sec.injectHeader)
	}
	if sec.injectQueryParam != "" {
		q := req.URL.Query()
		q.Set(sec.injectQueryParam, formatted)
		req.URL.RawQuery = q.Encode()
		locations = append(locations, "query:"+sec.injectQueryParam)
	}
	return locations, nil
}

func (s *Secrets) formatValue(sec *resolvedSecret, realValue string) (string, error) {
	if sec.formatter == nil {
		return realValue, nil
	}
	var buf strings.Builder
	if err := sec.formatter.Execute(&buf, formatterData{Value: realValue}); err != nil {
		return "", fmt.Errorf("executing formatter: %w", err)
	}
	return buf.String(), nil
}

// sentinelInRequest reports whether proxyValue occurs in any request header
// value, the URL path, the query string or, when body is non-nil, the
// scanned body (see scannableBody; pass nil to skip the body).
func sentinelInRequest(req *http.Request, proxyValue string, body []byte) bool {
	if body != nil && bytes.Contains(body, []byte(proxyValue)) {
		return true
	}
	for name, vals := range req.Header {
		for _, v := range vals {
			if headerContains(name, v, proxyValue) {
				return true
			}
		}
	}
	if req.URL == nil {
		return false
	}
	if strings.Contains(req.URL.Path, proxyValue) ||
		strings.Contains(req.URL.RawPath, proxyValue) ||
		strings.Contains(req.URL.RawQuery, proxyValue) {
		return true
	}
	decoded, err := url.QueryUnescape(req.URL.RawQuery)
	return err == nil && strings.Contains(decoded, proxyValue)
}

// isWebSocketUpgrade detects a WebSocket upgrade request. Connection is
// parsed as comma-separated tokens with an exact case-insensitive "upgrade"
// match.
func isWebSocketUpgrade(req *http.Request) bool {
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, v := range req.Header.Values("Connection") {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), "upgrade") {
				return true
			}
		}
	}
	return false
}

// addRedactPair records a substitution for response redaction, skipping
// real values already recorded.
func addRedactPair(tctx *transform.TransformContext, real, placeholder string) {
	for _, p := range tctx.RedactPairs {
		if p.Real == real {
			return
		}
	}
	tctx.RedactPairs = append(tctx.RedactPairs, transform.RedactPair{Real: real, Placeholder: placeholder})
}

// addBasicAuthPair records the re-encoded Basic credentials of a changed
// Authorization header, so an echo of the whole base64 payload is redacted
// back to the payload the client sent.
func addBasicAuthPair(tctx *transform.TransformContext, headerName, oldValue, newValue string) {
	if oldValue == newValue || !strings.EqualFold(headerName, "Authorization") {
		return
	}
	oldPayload, okOld := strings.CutPrefix(oldValue, "Basic ")
	newPayload, okNew := strings.CutPrefix(newValue, "Basic ")
	if okOld && okNew {
		addRedactPair(tctx, newPayload, oldPayload)
	}
}

// rejectResult builds an ActionReject result carrying a plain-text response.
func rejectResult(req *http.Request, status int, msg string) *transform.TransformResult {
	body := []byte(msg + "\n")
	return &transform.TransformResult{
		Action: transform.ActionReject,
		Response: &http.Response{
			StatusCode: status,
			Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Content-Type":           {"text/plain; charset=utf-8"},
				"X-Content-Type-Options": {"nosniff"},
			},
			Body:          transform.NewBufferedBodyFromBytes(body),
			ContentLength: int64(len(body)),
			Request:       req,
		},
	}
}

func (s *Secrets) swapHeaders(tctx *transform.TransformContext, req *http.Request, sec *resolvedSecret, realValue string) []string {
	var locations []string
	if len(sec.matchHeaders) == 0 {
		for name, vals := range req.Header {
			for i, v := range vals {
				if headerContains(name, v, sec.proxyValue) {
					replaced := replaceInHeader(name, v, sec.proxyValue, realValue)
					req.Header[name][i] = replaced
					addBasicAuthPair(tctx, name, v, replaced)
					locations = append(locations, "header:"+name)
				}
			}
		}
		return locations
	}

	processed := make(map[string]struct{})
	// swap scans the header identified by its canonical name and, on a match,
	// rewrites it under wireName so the user's requested casing is sent over
	// the wire. For regex matches wireName is the header's existing casing.
	swap := func(canonical, wireName string) {
		if _, done := processed[canonical]; done {
			return
		}
		processed[canonical] = struct{}{}
		hit := false
		headers.Swap(req.Header, canonical, wireName, func(v string) string {
			if headerContains(canonical, v, sec.proxyValue) {
				hit = true
			}
			replaced := replaceInHeader(canonical, v, sec.proxyValue, realValue)
			addBasicAuthPair(tctx, canonical, v, replaced)
			return replaced
		})
		if hit {
			locations = append(locations, "header:"+wireName)
		}
	}
	for _, m := range sec.matchHeaders {
		if m.re != nil {
			for name := range req.Header {
				if m.re.MatchString(name) {
					swap(name, name)
				}
			}
			continue
		}
		swap(m.name, m.wireName)
	}
	return locations
}

// replaceInHeader performs a secret replacement in a header value. For
// Authorization headers with HTTP Basic auth, the base64 payload is decoded
// before replacement and re-encoded after.
func replaceInHeader(headerName, value, proxyValue, realValue string) string {
	if strings.EqualFold(headerName, "Authorization") {
		if decoded, ok := decodeBasicAuth(value); ok {
			replaced := strings.ReplaceAll(decoded, proxyValue, realValue)
			return "Basic " + base64.StdEncoding.EncodeToString([]byte(replaced))
		}
	}
	return strings.ReplaceAll(value, proxyValue, realValue)
}

// headerContains checks whether a header value contains the proxy token.
// For Authorization headers with HTTP Basic auth, the base64 payload is
// decoded before checking.
func headerContains(headerName, value, proxyValue string) bool {
	if strings.EqualFold(headerName, "Authorization") {
		if decoded, ok := decodeBasicAuth(value); ok {
			return strings.Contains(decoded, proxyValue)
		}
	}
	return strings.Contains(value, proxyValue)
}

// decodeBasicAuth extracts and base64-decodes the payload from a "Basic ..."
// Authorization header value. Returns the decoded string and true on success.
func decodeBasicAuth(value string) (string, bool) {
	after, ok := strings.CutPrefix(value, "Basic ")
	if !ok {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(after)
	if err != nil {
		return "", false
	}
	return string(decoded), true
}

func (s *Secrets) swapQuery(req *http.Request, sec *resolvedSecret, realValue string) []string {
	raw := req.URL.RawQuery
	if raw == "" || !strings.Contains(raw, sec.proxyValue) {
		return nil
	}

	params, err := url.ParseQuery(raw)
	if err != nil {
		return nil
	}

	var locations []string
	for key, vals := range params {
		for i, v := range vals {
			if strings.Contains(v, sec.proxyValue) {
				params[key][i] = strings.ReplaceAll(v, sec.proxyValue, realValue)
				locations = append(locations, "query:"+key)
			}
		}
	}

	if len(locations) > 0 {
		req.URL.RawQuery = params.Encode()
	}
	return locations
}

func (s *Secrets) swapPath(req *http.Request, sec *resolvedSecret, realValue string) string {
	path := req.URL.Path
	if path == "" || !strings.Contains(path, sec.proxyValue) {
		return ""
	}
	req.URL.Path = strings.ReplaceAll(path, sec.proxyValue, realValue)
	// RawPath is an optional encoded form; clear it so net/http re-derives
	// the encoding from the new Path.
	req.URL.RawPath = ""
	return "path"
}

func (s *Secrets) swapBody(req *http.Request, sec *resolvedSecret, realValue string) string {
	if req.Body == nil {
		return ""
	}

	// An earlier entry may have read the body to EOF without replacing it.
	bb, buffered := req.Body.(*transform.BufferedBody)
	if buffered {
		bb.Reset()
	}

	data, err := io.ReadAll(req.Body)
	if err != nil {
		return ""
	}
	// A truncated body is never forwarded (the proxy answers 413), so do not
	// spend a substitution on it.
	if buffered && bb.Truncated() {
		return ""
	}

	if !bytes.Contains(data, []byte(sec.proxyValue)) {
		return ""
	}

	replaced := bytes.ReplaceAll(data, []byte(sec.proxyValue), []byte(escapeReal(requestBodyKind(req), realValue)))
	req.Body = transform.NewBufferedBodyFromBytes(replaced)
	return "body"
}
