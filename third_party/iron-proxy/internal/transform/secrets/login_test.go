package secrets

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

const (
	loginSentinel  = "asm_login_sentinel_0123456789abcdef"
	loginSentinel2 = "asm_login_sentinel_fedcba9876543210"
	loginReal      = `p&ss="x\y`
	loginFormReal  = `p%26ss%3D%22x%5Cy`
	loginJSONReal  = `"p&ss=\"x\\y"`
	loginOwner     = "h1"
	formType       = "application/x-www-form-urlencoded"
	jsonType       = "application/json"
)

// loginFixture holds a login entry's value file and claim file paths.
type loginFixture struct {
	valueFile string
	claimFile string
}

func newLoginFixture(t *testing.T) loginFixture {
	t.Helper()
	dir := t.TempDir()
	f := loginFixture{
		valueFile: filepath.Join(dir, "value"),
		claimFile: filepath.Join(dir, "claims", "grant.used"),
	}
	require.NoError(t, os.WriteFile(f.valueFile, []byte(loginReal), 0o600))
	require.NoError(t, os.Mkdir(filepath.Dir(f.claimFile), 0o700))
	return f
}

// entry returns a login entry for POST|PUT|PATCH https://login.test:443/session.
func (f loginFixture) entry(t *testing.T, sentinel string) secretEntry {
	t.Helper()
	return secretEntry{
		Source: yamlNode(t, map[string]string{"type": "file", "path": f.valueFile}),
		Rules:  []hostmatch.RuleConfig{{Host: "login.test", Methods: []string{"POST", "PUT", "PATCH"}}},
		Replace: &replaceConfig{
			ProxyValue: sentinel,
			Login:      &loginConfig{Port: 443, Target: "/session", Owner: loginOwner, ClaimFile: f.claimFile},
		},
	}
}

func makeLoginSecrets(t *testing.T, entries ...secretEntry) *Secrets {
	t.Helper()
	reg := testRegistry()
	reg["file"] = newFileBuilder(slog.Default())
	s, err := newFromConfig(secretsConfig{Secrets: entries}, reg)
	require.NoError(t, err)
	return s
}

func runTransform(t *testing.T, s *Secrets, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, string) {
	t.Helper()
	res, err := s.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	if res.Response == nil {
		return res, ""
	}
	msg, err := io.ReadAll(res.Response.Body)
	require.NoError(t, err)
	return res, string(msg)
}

func readBody(t *testing.T, req *http.Request) string {
	t.Helper()
	data, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	return string(data)
}

func TestLogin_Substitutes(t *testing.T) {
	cases := []struct {
		name        string
		method      string
		contentType string
		body        string
		want        string
		tunnelUser  string
	}{
		{"form", "POST", formType, "user=a&password=" + loginSentinel, "user=a&password=" + loginFormReal, ""},
		{"json", "POST", jsonType, `{"user":{"pw":"` + loginSentinel + `"}}`, `{"user":{"pw":` + loginJSONReal + `}}`, ""},
		{"json suffix, PUT", "PUT", "application/vnd.login+json", `{"pw":"` + loginSentinel + `"}`, `{"pw":` + loginJSONReal + `}`, ""},
		{"owner's tunnel", "PATCH", formType, "password=" + loginSentinel, "password=" + loginFormReal, loginOwner},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newLoginFixture(t)
			s := makeLoginSecrets(t, f.entry(t, loginSentinel))
			req := bodyReq("https://login.test/session", tc.contentType, tc.body)
			req.Method = tc.method
			req.Header.Set("Range", "bytes=0-10")
			req.Header.Set("Accept-Encoding", "gzip")
			tctx := &transform.TransformContext{TunnelUser: tc.tunnelUser}

			res, _ := runTransform(t, s, tctx, req)
			require.Equal(t, transform.ActionContinue, res.Action)
			require.Equal(t, tc.want, readBody(t, req))
			require.Empty(t, req.Header.Get("Range"))
			require.Empty(t, req.Header.Get("Accept-Encoding"))
			require.Equal(t, []transform.RedactPair{{Real: loginReal, Placeholder: loginSentinel}}, tctx.RedactPairs)
			require.Equal(t, []secretRecord{{Secret: f.valueFile, Locations: []string{"body"}}}, tctx.DrainAnnotations()["swapped"])

			claimed, err := os.ReadFile(f.claimFile)
			require.NoError(t, err)
			_, err = time.Parse(time.RFC3339, string(claimed))
			require.NoError(t, err)

			// The grant is single use.
			again := bodyReq("https://login.test/session", tc.contentType, tc.body)
			tctx = &transform.TransformContext{TunnelUser: tc.tunnelUser}
			res, msg := runTransform(t, s, tctx, again)
			require.Equal(t, transform.ActionReject, res.Action)
			require.Equal(t, http.StatusForbidden, res.Response.StatusCode)
			require.Equal(t, msgSentinelEnded+"\n", msg)
			require.Equal(t, "sentinel_ended", tctx.DrainAnnotations()["reject_reason"])
			require.Equal(t, tc.body, readBody(t, again))
		})
	}
}

func TestLogin_Rejections(t *testing.T) {
	notValid := func(target string) string {
		return "asm: login sentinel not valid for POST " + target
	}
	cases := []struct {
		name        string
		url         string
		contentType string
		body        string
		prepare     func(t *testing.T, f loginFixture, req *http.Request)
		tunnelUser  string
		twoGrants   bool
		wantStatus  int
		wantMsg     string
		wantReason  string
	}{
		{name: "sentinel as key", url: "https://login.test/session", contentType: jsonType,
			body: `{"` + loginSentinel + `":"x"}`, wantStatus: 403, wantMsg: msgLoginValue, wantReason: "login_value"},
		{name: "sentinel inside a longer value", url: "https://login.test/session", contentType: formType,
			body: "password=x" + loginSentinel, wantStatus: 403, wantMsg: msgLoginValue, wantReason: "login_value"},
		{name: "sentinel twice", url: "https://login.test/session", contentType: formType,
			body: "password=" + loginSentinel + "&confirm=" + loginSentinel, wantStatus: 403, wantMsg: msgLoginValue, wantReason: "login_value"},
		{name: "two grants in one body", url: "https://login.test/session", contentType: formType,
			body: "a=" + loginSentinel + "&b=" + loginSentinel2, twoGrants: true, wantStatus: 403, wantMsg: msgLoginMulti, wantReason: "login_multi"},
		{name: "query not in target", url: "https://login.test/session?x=1", contentType: formType,
			body: "password=" + loginSentinel, wantStatus: 403, wantMsg: notValid("https://login.test:443/session?x=1"), wantReason: "login_scope"},
		{name: "different path", url: "https://login.test/other", contentType: formType,
			body: "password=" + loginSentinel, wantStatus: 403, wantMsg: notValid("https://login.test:443/other"), wantReason: "login_scope"},
		{name: "different host", url: "https://evil.test/session", contentType: formType,
			body: "password=" + loginSentinel, wantStatus: 403, wantMsg: notValid("https://evil.test:443/session"), wantReason: "login_scope"},
		{name: "different port", url: "https://login.test:8443/session", contentType: formType,
			body: "password=" + loginSentinel, wantStatus: 403, wantMsg: notValid("https://login.test:8443/session"), wantReason: "login_scope"},
		{name: "plain http", url: "http://login.test/session", contentType: formType,
			body: "password=" + loginSentinel, wantStatus: 403, wantMsg: notValid("http://login.test:80/session"), wantReason: "login_scope"},
		{name: "header sentinel", url: "https://login.test/session", contentType: formType,
			body: "user=a",
			prepare: func(_ *testing.T, _ loginFixture, req *http.Request) {
				req.Header.Set("X-Password", loginSentinel)
			},
			wantStatus: 403, wantMsg: msgLoginValue, wantReason: "login_value"},
		{name: "multipart with sentinel", url: "https://login.test/session", contentType: "multipart/form-data; boundary=b",
			body:       "--b\r\nContent-Disposition: form-data; name=\"pw\"\r\n\r\n" + loginSentinel + "\r\n--b--\r\n",
			wantStatus: 403, wantMsg: msgLoginBody, wantReason: "login_body"},
		{name: "multipart without sentinel", url: "https://login.test/session", contentType: "multipart/form-data; boundary=b",
			body:       "--b\r\nContent-Disposition: form-data; name=\"pw\"\r\n\r\nx\r\n--b--\r\n",
			wantStatus: 403, wantMsg: msgLoginBody, wantReason: "login_body"},
		{name: "gzip body", url: "https://login.test/session", contentType: formType,
			body: "\x1f\x8b opaque",
			prepare: func(_ *testing.T, _ loginFixture, req *http.Request) {
				req.Header.Set("Content-Encoding", "gzip")
			},
			wantStatus: 403, wantMsg: msgLoginBody, wantReason: "login_body"},
		{name: "truncated body", url: "https://login.test/session", contentType: formType,
			body: "user=a&password=" + loginSentinel,
			prepare: func(_ *testing.T, _ loginFixture, req *http.Request) {
				req.Body = transform.NewBufferedBody(io.NopCloser(strings.NewReader("user=a&password="+loginSentinel)), 8)
				req.ContentLength = -1
			},
			wantStatus: 403, wantMsg: msgLoginBody, wantReason: "login_body"},
		{name: "declared over limit", url: "https://login.test/session", contentType: formType,
			body: "user=a&password=" + loginSentinel,
			prepare: func(_ *testing.T, _ loginFixture, req *http.Request) {
				req.Body = transform.NewBufferedBody(io.NopCloser(strings.NewReader("user=a&password="+loginSentinel)), 8)
			},
			wantStatus: 403, wantMsg: msgLoginBody, wantReason: "login_body"},
		{name: "other content type", url: "https://login.test/session", contentType: "text/plain",
			body: "password=" + loginSentinel, wantStatus: 403, wantMsg: msgLoginBody, wantReason: "login_body"},
		{name: "missing value file", url: "https://login.test/session", contentType: formType,
			body: "password=" + loginSentinel,
			prepare: func(t *testing.T, f loginFixture, _ *http.Request) {
				require.NoError(t, os.Remove(f.valueFile))
			},
			wantStatus: 503, wantMsg: msgLoginUnavailable, wantReason: "secret_unavailable"},
		{name: "another machine's tunnel", url: "https://login.test/session", contentType: formType,
			body: "password=" + loginSentinel, tunnelUser: "h2",
			wantStatus: 403, wantMsg: msgLoginOwner, wantReason: "login_owner"},
		{name: "malformed json", url: "https://login.test/session", contentType: jsonType,
			body: `{"pw":"` + loginSentinel + `"`, wantStatus: 403, wantMsg: msgLoginValue, wantReason: "login_value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newLoginFixture(t)
			entries := []secretEntry{f.entry(t, loginSentinel)}
			if tc.twoGrants {
				second := newLoginFixture(t)
				entries = append(entries, second.entry(t, loginSentinel2))
			}
			s := makeLoginSecrets(t, entries...)
			req := bodyReq(tc.url, tc.contentType, tc.body)
			if tc.prepare != nil {
				tc.prepare(t, f, req)
			}
			tctx := &transform.TransformContext{TunnelUser: tc.tunnelUser}

			res, msg := runTransform(t, s, tctx, req)
			require.Equal(t, transform.ActionReject, res.Action)
			require.Equal(t, tc.wantStatus, res.Response.StatusCode)
			require.Equal(t, tc.wantMsg+"\n", msg)
			require.Equal(t, tc.wantReason, tctx.DrainAnnotations()["reject_reason"])
			require.Empty(t, tctx.RedactPairs)
			require.NoFileExists(t, f.claimFile)
			require.NotContains(t, readBody(t, req), loginReal)
		})
	}
}

func TestLogin_OtherRejectionDoesNotClaim(t *testing.T) {
	cases := []struct {
		name    string
		extra   []secretEntry
		prepare func(req *http.Request)
		status  int
		wantMsg string
	}{
		{"out-of-scope exec sentinel", []secretEntry{defaultEntry()}, func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer proxy-openai-abc123")
		}, http.StatusForbidden, msgSentinelNotValid + "\n"},
		{"websocket upgrade", nil, func(req *http.Request) {
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Connection", "Upgrade")
		}, http.StatusForbidden, msgWebSocketSwap + "\n"},
		{"co-hosted require entry", []secretEntry{{
			Source:  envSource("INTERNAL_TOKEN"),
			Rules:   []hostmatch.RuleConfig{{Host: "login.test"}},
			Replace: &replaceConfig{ProxyValue: "proxy-internal-tok", MatchHeaders: []string{"X-Api-Key"}, Require: true},
		}}, func(*http.Request) {}, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newLoginFixture(t)
			s := makeLoginSecrets(t, append([]secretEntry{f.entry(t, loginSentinel)}, tc.extra...)...)
			body := "user=a&password=" + loginSentinel

			req := bodyReq("https://login.test/session", formType, body)
			tc.prepare(req)
			tctx := &transform.TransformContext{}
			res, msg := runTransform(t, s, tctx, req)
			require.Equal(t, transform.ActionReject, res.Action)
			if tc.status != 0 {
				require.Equal(t, tc.status, res.Response.StatusCode)
				require.Equal(t, tc.wantMsg, msg)
			}
			require.NoFileExists(t, f.claimFile)
			require.Empty(t, tctx.RedactPairs)
			require.Equal(t, body, readBody(t, req))

			// The grant is still usable by a clean request.
			clean := bodyReq("https://login.test/session", formType, body)
			if tc.status == 0 {
				clean.Header.Set("X-Api-Key", "proxy-internal-tok")
			}
			res, _ = runTransform(t, s, &transform.TransformContext{}, clean)
			require.Equal(t, transform.ActionContinue, res.Action)
			require.Equal(t, "user=a&password="+loginFormReal, readBody(t, clean))
			require.FileExists(t, f.claimFile)
		})
	}
}

func TestLogin_KeepsCoHostedBodySwap(t *testing.T) {
	f := newLoginFixture(t)
	s := makeLoginSecrets(t, f.entry(t, loginSentinel), secretEntry{
		Source:  envSource("INTERNAL_TOKEN"),
		Rules:   []hostmatch.RuleConfig{{Host: "login.test"}},
		Replace: &replaceConfig{ProxyValue: "proxy-internal-tok", MatchBody: true},
	})
	req := bodyReq("https://login.test/session", formType, "csrf=proxy-internal-tok&password="+loginSentinel)
	tctx := &transform.TransformContext{}
	res, _ := runTransform(t, s, tctx, req)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "csrf=real-internal-token&password="+loginFormReal, readBody(t, req))
	require.FileExists(t, f.claimFile)
}

func TestLogin_ClaimFailure(t *testing.T) {
	f := newLoginFixture(t)
	f.claimFile = filepath.Join(filepath.Dir(f.claimFile), "missing", "grant.used")
	s := makeLoginSecrets(t, f.entry(t, loginSentinel))
	body := "user=a&password=" + loginSentinel
	req := bodyReq("https://login.test/session", formType, body)
	tctx := &transform.TransformContext{}

	res, msg := runTransform(t, s, tctx, req)
	require.Equal(t, transform.ActionReject, res.Action)
	require.Equal(t, http.StatusForbidden, res.Response.StatusCode)
	require.Equal(t, msgSentinelEnded+"\n", msg)
	annotations := tctx.DrainAnnotations()
	require.Equal(t, "sentinel_ended", annotations["reject_reason"])
	require.Contains(t, annotations["claim_error"], "no such file or directory")
	require.NotContains(t, annotations["claim_error"], loginReal)
	require.Empty(t, tctx.RedactPairs)
	require.Equal(t, body, readBody(t, req))
	require.NoFileExists(t, f.claimFile)
}

func TestLogin_EndpointWithoutSentinelPassesThrough(t *testing.T) {
	f := newLoginFixture(t)
	s := makeLoginSecrets(t, f.entry(t, loginSentinel))
	req := bodyReq("https://login.test/session", formType, "user=a&password=typed-by-hand")

	res, _ := runTransform(t, s, &transform.TransformContext{}, req)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "user=a&password=typed-by-hand", readBody(t, req))
	require.NoFileExists(t, f.claimFile)
}

func TestLogin_ConcurrentRequestsSubstituteOnce(t *testing.T) {
	f := newLoginFixture(t)
	s := makeLoginSecrets(t, f.entry(t, loginSentinel))

	const n = 16
	results := make([]*transform.TransformResult, n)
	bodies := make([]string, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := bodyReq("https://login.test/session", formType, "password="+loginSentinel)
			<-start
			res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
			if err != nil {
				return // results[i] stays nil and fails the count below
			}
			data, err := io.ReadAll(req.Body)
			if err != nil {
				return // bodies[i] stays empty and fails the count below
			}
			results[i] = res
			bodies[i] = string(data)
		}()
	}
	close(start)
	wg.Wait()

	substituted, ended := 0, 0
	for i, res := range results {
		require.NotNil(t, res)
		switch res.Action {
		case transform.ActionContinue:
			substituted++
			require.Equal(t, "password="+loginFormReal, bodies[i])
		case transform.ActionReject:
			ended++
			require.Equal(t, http.StatusForbidden, res.Response.StatusCode)
			require.Equal(t, "password="+loginSentinel, bodies[i])
		}
	}
	require.Equal(t, 1, substituted)
	require.Equal(t, n-1, ended)
	require.FileExists(t, f.claimFile)
}

func TestLogin_ConfigErrors(t *testing.T) {
	const only = "login entries take only proxy_value, login and rules"
	const rule = "login entries take exactly one rule with one literal host, no cidr or paths, and methods POST, PUT, PATCH"
	cases := []struct {
		name   string
		mutate func(e *secretEntry)
		errMsg string
	}{
		{"match_body", func(e *secretEntry) { e.Replace.MatchBody = true }, only},
		{"match_headers", func(e *secretEntry) { e.Replace.MatchHeaders = []string{"X-Pw"} }, only},
		{"match_path", func(e *secretEntry) { e.Replace.MatchPath = true }, only},
		{"match_query", func(e *secretEntry) { e.Replace.MatchQuery = true }, only},
		{"require", func(e *secretEntry) { e.Replace.Require = true }, only},
		{"allow_plain_http", func(e *secretEntry) { e.Replace.AllowPlainHTTP = true }, only},
		{"ended", func(e *secretEntry) { e.Replace.Ended = true }, only},
		{"port 0", func(e *secretEntry) { e.Replace.Login.Port = 0 }, "login.port must be 1-65535"},
		{"port too large", func(e *secretEntry) { e.Replace.Login.Port = 65536 }, "login.port must be 1-65535"},
		{"relative target", func(e *secretEntry) { e.Replace.Login.Target = "session" }, "login.target must start with /"},
		{"no owner", func(e *secretEntry) { e.Replace.Login.Owner = "" }, "login.owner is required"},
		{"no claim file", func(e *secretEntry) { e.Replace.Login.ClaimFile = "" }, "login.claim_file must be an absolute path"},
		{"relative claim file", func(e *secretEntry) { e.Replace.Login.ClaimFile = "claims/x" }, "login.claim_file must be an absolute path"},
		{"two rules", func(e *secretEntry) { e.Rules = append(e.Rules, e.Rules[0]) }, rule},
		{"cidr", func(e *secretEntry) {
			e.Rules[0] = hostmatch.RuleConfig{CIDR: "10.0.0.0/8", Methods: e.Rules[0].Methods}
		}, rule},
		{"no methods", func(e *secretEntry) { e.Rules[0].Methods = nil }, rule},
		{"GET method", func(e *secretEntry) { e.Rules[0].Methods = []string{"POST", "PUT", "GET"} }, rule},
		{"duplicate method", func(e *secretEntry) { e.Rules[0].Methods = []string{"POST", "POST", "PUT"} }, rule},
		{"wildcard host", func(e *secretEntry) { e.Rules[0].Host = "*.login.test" }, rule},
		{"glob ? host", func(e *secretEntry) { e.Rules[0].Host = "login?.test" }, rule},
		{"glob class host", func(e *secretEntry) { e.Rules[0].Host = "login[0-9].test" }, rule},
		{"escaped host", func(e *secretEntry) { e.Rules[0].Host = `login\.test` }, rule},
		{"paths", func(e *secretEntry) { e.Rules[0].Paths = []string{"/session"} }, rule},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newLoginFixture(t).entry(t, loginSentinel)
			tc.mutate(&e)
			reg := testRegistry()
			reg["file"] = newFileBuilder(slog.Default())
			_, err := newFromConfig(secretsConfig{Secrets: []secretEntry{e}}, reg)
			require.Error(t, err)
			require.Contains(t, err.Error(), "secrets[0]: "+tc.errMsg)
		})
	}
}

func TestLogin_YAMLConfig(t *testing.T) {
	f := newLoginFixture(t)
	src := `
secrets:
  - source: {type: file, path: ` + f.valueFile + `}
    rules: [{host: login.test, methods: [POST, PUT, PATCH]}]
    replace:
      proxy_value: ` + loginSentinel + `
      login: {port: 443, target: "/session", owner: h1, claim_file: ` + f.claimFile + `}
browser_hosts:
  - {host: login.test, port: 443, until: 4102444800}
`
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(src), &node))
	tr, err := factory(*node.Content[0], slog.Default())
	require.NoError(t, err)
	s := tr.(*Secrets)
	require.Equal(t, []browserHostConfig{{Host: "login.test", Port: 443, Until: 4102444800}}, s.browserHosts)
	require.Len(t, s.secrets, 1)
	require.Equal(t, &loginConfig{Port: 443, Target: "/session", Owner: "h1", ClaimFile: f.claimFile}, s.secrets[0].login)

	req := bodyReq("https://login.test/session", formType, "password="+loginSentinel)
	res, _ := runTransform(t, s, &transform.TransformContext{}, req)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "password="+loginFormReal, readBody(t, req))
}

// connectReq builds the synthetic CONNECT request the proxy runs through the
// pipeline for a tunnel (see proxy.tunnelTransformCheck).
func connectReq(target, marker string) *http.Request {
	hdr := http.Header{}
	if marker != "" {
		hdr.Set("Asm-Browser-Route", marker)
	}
	req := &http.Request{
		Method:     http.MethodConnect,
		Host:       target,
		URL:        &url.URL{Host: target},
		Header:     hdr,
		RemoteAddr: "127.0.0.1:50000",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	req.Body = transform.NewBufferedBody(http.NoBody, 0)
	return req
}

func TestBrowserRoute(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	past := time.Now().Add(-time.Second).Unix()
	cases := []struct {
		name      string
		target    string
		marker    string
		withLogin bool
		wantAllow bool
		wantDeny  bool
	}{
		{name: "listed and live", target: "login.test:443", marker: "1", wantAllow: true},
		{name: "listed, host case differs", target: "LOGIN.Test:443", marker: "1", wantAllow: true},
		{name: "listed with a login entry", target: "login.test:443", marker: "1", withLogin: true, wantAllow: true},
		{name: "other port", target: "login.test:8443", marker: "1", wantDeny: true},
		{name: "unlisted", target: "other.test:443", marker: "1", wantDeny: true},
		{name: "expired", target: "old.test:443", marker: "1", wantDeny: true},
		{name: "no port", target: "login.test", marker: "1", wantDeny: true},
		{name: "unmarked", target: "other.test:443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var entries []secretEntry
			if tc.withLogin {
				entries = append(entries, newLoginFixture(t).entry(t, loginSentinel))
			}
			reg := testRegistry()
			reg["file"] = newFileBuilder(slog.Default())
			s, err := newFromConfig(secretsConfig{
				Secrets: entries,
				BrowserHosts: []browserHostConfig{
					{Host: "login.test", Port: 443, Until: future},
					{Host: "old.test", Port: 443, Until: past},
				},
			}, reg)
			require.NoError(t, err)

			tctx := &transform.TransformContext{}
			res, msg := runTransform(t, s, tctx, connectReq(tc.target, tc.marker))
			annotations := tctx.DrainAnnotations()
			if tc.wantDeny {
				require.Equal(t, transform.ActionReject, res.Action)
				require.Equal(t, http.StatusForbidden, res.Response.StatusCode)
				require.Equal(t, msgBrowserRoute+"\n", msg)
				require.Equal(t, "browser_route", annotations["reject_reason"])
				require.NotContains(t, annotations, "browser_route")
				return
			}
			require.Equal(t, transform.ActionContinue, res.Action)
			if tc.wantAllow {
				require.Equal(t, "allowed", annotations["browser_route"])
			} else {
				require.NotContains(t, annotations, "browser_route")
			}
		})
	}
}

func TestBrowserRoute_NoBrowserHostsDenies(t *testing.T) {
	s := makeSecrets(t, nil)
	tctx := &transform.TransformContext{}
	res, msg := runTransform(t, s, tctx, connectReq("login.test:443", "1"))
	require.Equal(t, transform.ActionReject, res.Action)
	require.Equal(t, msgBrowserRoute+"\n", msg)
	require.Equal(t, "browser_route", tctx.DrainAnnotations()["reject_reason"])
}

func TestBrowserHosts_ConfigErrors(t *testing.T) {
	cases := []struct {
		name   string
		host   browserHostConfig
		errMsg string
	}{
		{"uppercase host", browserHostConfig{Host: "Login.test", Port: 443, Until: 1}, "browser_hosts[0]: host must be non-empty and lowercase"},
		{"empty host", browserHostConfig{Port: 443, Until: 1}, "browser_hosts[0]: host must be non-empty and lowercase"},
		{"port 0", browserHostConfig{Host: "login.test", Until: 1}, "browser_hosts[0]: port must be 1-65535"},
		{"port too large", browserHostConfig{Host: "login.test", Port: 70000, Until: 1}, "browser_hosts[0]: port must be 1-65535"},
		{"until 0", browserHostConfig{Host: "login.test", Port: 443}, "browser_hosts[0]: until must be positive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newFromConfig(secretsConfig{BrowserHosts: []browserHostConfig{tc.host}}, testRegistry())
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errMsg)
		})
	}
}
