package proxy

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/transform"
	_ "github.com/ironsh/iron-proxy/internal/transform/secrets" // registers the secrets transform
)

const (
	testSentinel = "asm_0123456789abcdefghijABCDEFGHIJ0123456789"
	testReal     = "real-value-123456"
)

// echoUpstream records each request's X-Key and Accept-Encoding and echoes
// X-Key in the body, gzip-compressed when the request accepts gzip.
type echoUpstream struct {
	mu       sync.Mutex
	keys     []string
	encoding []string
}

func (e *echoUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	e.keys = append(e.keys, r.Header.Get("X-Key"))
	e.encoding = append(e.encoding, r.Header.Get("Accept-Encoding"))
	e.mu.Unlock()

	_, _ = io.Copy(io.Discard, r.Body) // drain; the body is irrelevant here
	body := "echo=" + r.Header.Get("X-Key")
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = io.WriteString(gz, body) // a failed write surfaces as a client-side assertion
		_ = gz.Close()
		return
	}
	_, _ = io.WriteString(w, body) // a failed write surfaces as a client-side assertion
}

func (e *echoUpstream) seen() (keys, encoding []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.keys...), append([]string(nil), e.encoding...)
}

// startSecretsProxy starts the HTTP and tunnel listeners with a secrets
// transform built from cfg. Upstream connections all go to upstreamAddr,
// through the production transport (so its compression handling is the one
// under test).
func startSecretsProxy(t *testing.T, cfg string, limits transform.BodyLimits, upstreamAddr string) (httpAddr, tunnelAddr string, pool *x509.CertPool) {
	t.Helper()

	factory, err := transform.Lookup("secrets")
	require.NoError(t, err)
	tr, err := factory(mustYAMLNode(t, cfg), testLogger())
	require.NoError(t, err)

	caCert, caKey := generateTestCA(t)
	cache, err := certcache.NewFromCA(caCert, caKey, 100, 72*time.Hour)
	require.NoError(t, err)

	p := New(Options{
		HTTPAddr:   "127.0.0.1:0",
		HTTPSAddr:  "127.0.0.1:0",
		TunnelAddr: "127.0.0.1:0",
		CertCache:  cache,
		Pipeline:   transform.NewPipelineHolder(transform.NewPipeline([]transform.Transformer{tr}, limits, testLogger())),
		Logger:     testLogger(),
	})
	p.transport.TLSClientConfig.InsecureSkipVerify = true
	p.transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
	}

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.httpServer.Serve(httpLn) }()

	tunnelLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p.tunnelListener = tunnelLn
	go func() {
		for {
			conn, err := tunnelLn.Accept()
			if err != nil {
				return
			}
			go p.handleTunnel(conn)
		}
	}()

	t.Cleanup(func() {
		_ = p.httpServer.Close()
		_ = tunnelLn.Close()
		close(p.tunnelDone)
	})

	pool = x509.NewCertPool()
	pool.AddCert(caCert)
	return httpLn.Addr().String(), tunnelLn.Addr().String(), pool
}

func secretsConfig(host string, allowPlainHTTP bool) string {
	return fmt.Sprintf(`
secrets:
  - source: {type: env, var: ASM_TEST_TOKEN}
    replace: {proxy_value: %q, match_body: true, allow_plain_http: %t}
    rules: [{host: %q}]
`, testSentinel, allowPlainHTTP, host)
}

// TestSecrets_TunnelsSubstituteAndRedact proves requests inside MITM'd
// CONNECT and SOCKS5 tunnels arrive with req.TLS set (so the swap gate
// passes), and that a gzip upstream reaches the redactor decoded.
func TestSecrets_TunnelsSubstituteAndRedact(t *testing.T) {
	tests := []struct {
		name  string
		proxy func(tunnelAddr string) *url.URL
	}{
		{"CONNECT", func(addr string) *url.URL { return &url.URL{Scheme: "http", Host: addr} }},
		{"SOCKS5", func(addr string) *url.URL { return &url.URL{Scheme: "socks5", Host: addr} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ASM_TEST_TOKEN", testReal)
			echo := &echoUpstream{}
			upstream := httptest.NewTLSServer(echo)
			defer upstream.Close()

			_, tunnelAddr, pool := startSecretsProxy(t, secretsConfig("mitm.example.com", false), transform.BodyLimits{}, upstream.Listener.Addr().String())

			client := &http.Client{Transport: &http.Transport{
				Proxy:           http.ProxyURL(tc.proxy(tunnelAddr)),
				TLSClientConfig: &tls.Config{RootCAs: pool},
			}}
			defer client.CloseIdleConnections()

			req, err := http.NewRequest("GET", "https://mitm.example.com/echo", nil)
			require.NoError(t, err)
			req.Header.Set("X-Key", testSentinel)
			req.Header.Set("Accept-Encoding", "br")
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
			require.Equal(t, "echo="+testSentinel, string(body))
			require.Empty(t, resp.Header.Get("Content-Encoding"))

			keys, encoding := echo.seen()
			require.Equal(t, []string{testReal}, keys)
			// The client's "br" was dropped; Go's transport asked for gzip
			// itself and decoded it before the response transforms ran.
			require.Equal(t, []string{"gzip"}, encoding)
		})
	}
}

func TestSecrets_PlainHTTP(t *testing.T) {
	tests := []struct {
		name       string
		allow      bool
		wantStatus int
		wantKeys   []string
		wantBody   string
	}{
		{"refused by default", false, http.StatusForbidden, nil, "asm: sentinel not valid for this host or scheme\n"},
		{"allowed", true, http.StatusOK, []string{testReal}, "echo=" + testSentinel},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ASM_TEST_TOKEN", testReal)
			echo := &echoUpstream{}
			upstream := httptest.NewServer(echo)
			defer upstream.Close()

			httpAddr, _, _ := startSecretsProxy(t, secretsConfig("plain.example.com", tc.allow), transform.BodyLimits{}, upstream.Listener.Addr().String())

			req, err := http.NewRequest("GET", "http://"+httpAddr+"/echo", nil)
			require.NoError(t, err)
			req.Host = "plain.example.com"
			req.Header.Set("X-Key", testSentinel)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			require.Equal(t, tc.wantStatus, resp.StatusCode)
			require.Equal(t, tc.wantBody, string(body))
			keys, _ := echo.seen()
			require.Equal(t, tc.wantKeys, keys)
		})
	}
}

func TestSecrets_OversizedBodyRejected(t *testing.T) {
	t.Setenv("ASM_TEST_TOKEN", testReal)
	echo := &echoUpstream{}
	upstream := httptest.NewServer(echo)
	defer upstream.Close()

	httpAddr, _, _ := startSecretsProxy(t, secretsConfig("plain.example.com", true), transform.BodyLimits{MaxRequestBodyBytes: 64}, upstream.Listener.Addr().String())

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{"at limit", strings.Repeat("x", 64), http.StatusOK},
		{"over limit", testSentinel + strings.Repeat("x", 64), http.StatusRequestEntityTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", "http://"+httpAddr+"/echo", strings.NewReader(tc.body))
			require.NoError(t, err)
			req.Host = "plain.example.com"
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			require.Equal(t, tc.wantStatus, resp.StatusCode, string(body))
			if tc.wantStatus == http.StatusRequestEntityTooLarge {
				require.Equal(t, "asm: request body exceeds proxy.max_request_body_bytes\n", string(body))
			}
		})
	}
	keys, _ := echo.seen()
	require.Len(t, keys, 1, "the oversized request must not reach the upstream")
}
