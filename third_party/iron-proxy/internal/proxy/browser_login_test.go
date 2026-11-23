package proxy

// End-to-end tests of browser routes and login grants through the real
// secrets transform (asm fork). They pin the cross-package contract: the
// secrets transform annotates approved CONNECTs browser_route=allowed, and
// login substitution sees the tunnel user set by proxy authentication.

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
)

const (
	browserLoginSentinel = "asm_login_sentinel_0123456789abcdef"
	browserLoginReal     = `p&ss="x\y`
)

// newSecretsTransform builds the registered secrets transform from cfg.
func newSecretsTransform(t *testing.T, cfg string) transform.Transformer {
	t.Helper()
	factory, err := transform.Lookup("secrets")
	require.NoError(t, err)
	tr, err := factory(mustYAMLNode(t, cfg), testLogger())
	require.NoError(t, err)
	return tr
}

func TestBrowserRoute_RealSecretsTransform(t *testing.T) {
	until := time.Now().Add(time.Hour).Unix()
	tr := newSecretsTransform(t, fmt.Sprintf(`
browser_hosts:
  - {host: login.test, port: 443, until: %d}
  - {host: expired.test, port: 443, until: %d}
`, until, time.Now().Add(-time.Minute).Unix()))
	_, tunnelAddr, _, browserPool := startBrowserRouteProxy(t, []transform.Transformer{tr}, true, nil)

	t.Run("listed live host gets a browser CA leaf", func(t *testing.T) {
		conn, br := sendCONNECT(t, tunnelAddr, "login.test:443", "Asm-Browser-Route: 1\r\n")
		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusOK, resp.StatusCode)

		tlsConn := tls.Client(newPeekedConn(conn, br), &tls.Config{RootCAs: browserPool, ServerName: "login.test"})
		t.Cleanup(func() { _ = tlsConn.Close() })
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		require.NoError(t, tlsConn.Handshake())
		require.Equal(t, browserCACommonName, tlsConn.ConnectionState().PeerCertificates[0].Issuer.CommonName)
	})

	rejected := []struct {
		name   string
		target string
	}{
		{name: "unlisted host", target: "other.test:443"},
		{name: "listed host on another port", target: "login.test:8443"},
		{name: "expired host", target: "expired.test:443"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			conn, br := sendCONNECT(t, tunnelAddr, tc.target, "Asm-Browser-Route: 1\r\n")
			resp, err := http.ReadResponse(br, nil)
			require.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.Equal(t, http.StatusForbidden, resp.StatusCode)
			require.Contains(t, string(body), "no active login grant")
			require.Empty(t, readUntilClose(t, conn, br))
		})
	}
}

// loginUpstream records each request's body and declared Content-Length.
type loginUpstream struct {
	mu       sync.Mutex
	bodies   []string
	declared []int64
}

func (u *loginUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u.mu.Lock()
	u.bodies = append(u.bodies, string(body))
	u.declared = append(u.declared, r.ContentLength)
	u.mu.Unlock()
	_, _ = io.WriteString(w, "signed in") // a failed write surfaces as a client-side assertion
}

func (u *loginUpstream) seen() (bodies []string, declared []int64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.bodies...), append([]int64(nil), u.declared...)
}

func TestLogin_ThroughBrowserRoute(t *testing.T) {
	dir := t.TempDir()
	valueFile := filepath.Join(dir, "value")
	claimFile := filepath.Join(dir, "claims", "grant.used")
	require.NoError(t, os.WriteFile(valueFile, []byte(browserLoginReal), 0o600))
	require.NoError(t, os.Mkdir(filepath.Dir(claimFile), 0o700))

	tr := newSecretsTransform(t, fmt.Sprintf(`
secrets:
  - source: {type: file, path: %s}
    rules: [{host: login.test, methods: [POST, PUT, PATCH]}]
    replace:
      proxy_value: %s
      login: {port: 443, target: "/session", owner: h1, claim_file: %s}
browser_hosts:
  - {host: login.test, port: 443, until: %d}
`, valueFile, browserLoginSentinel, claimFile, time.Now().Add(time.Hour).Unix()))

	upstreamHandler := &loginUpstream{}
	upstream := httptest.NewTLSServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	authFile := writeAuthFile(t, map[string]string{"h1": "h1-pass", "h2": "h2-pass"})
	p, tunnelAddr, _, browserPool := startBrowserRouteProxy(t, []transform.Transformer{tr}, true, func(o *Options) {
		o.AuthFile = authFile
	})
	upstreamAddr := upstream.Listener.Addr().String()
	p.transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}

	form := "user=a&password=" + browserLoginSentinel
	// post submits the login form over a fresh browser-routed tunnel
	// authenticated as user and returns the status and body.
	post := func(t *testing.T, user string) (int, string) {
		t.Helper()
		conn, br := sendCONNECT(t, tunnelAddr, "login.test:443",
			"Asm-Browser-Route: 1\r\nProxy-Authorization: "+basicProxyAuth(user, user+"-pass")+"\r\n")
		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusOK, resp.StatusCode)

		tlsConn := tls.Client(newPeekedConn(conn, br), &tls.Config{RootCAs: browserPool, ServerName: "login.test"})
		t.Cleanup(func() { _ = tlsConn.Close() })
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		require.NoError(t, tlsConn.Handshake())

		req, err := http.NewRequest(http.MethodPost, "https://login.test/session", strings.NewReader(form))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		require.NoError(t, req.Write(tlsConn))
		resp, err = http.ReadResponse(bufio.NewReader(tlsConn), req)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		return resp.StatusCode, string(body)
	}

	// Another machine's tunnel cannot redeem the grant and does not consume it.
	status, body := post(t, "h2")
	require.Equal(t, http.StatusForbidden, status)
	require.Contains(t, body, "this login grant belongs to another machine")
	require.NoFileExists(t, claimFile)

	status, body = post(t, "h1")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "signed in", body)
	require.FileExists(t, claimFile)

	bodies, declared := upstreamHandler.seen()
	require.Len(t, bodies, 1)
	values, err := url.ParseQuery(bodies[0])
	require.NoError(t, err)
	require.Equal(t, browserLoginReal, values.Get("password"))
	require.Equal(t, "a", values.Get("user"))
	require.NotEqual(t, len(form), len(bodies[0]))
	require.Equal(t, int64(len(bodies[0])), declared[0])

	status, body = post(t, "h1")
	require.Equal(t, http.StatusForbidden, status)
	require.Contains(t, body, "asm: sentinel expired or revoked")

	bodies, _ = upstreamHandler.seen()
	require.Len(t, bodies, 1)
}
