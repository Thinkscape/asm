package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func startTunnelProxy(t *testing.T, transforms []transform.Transformer) (*Proxy, string, *x509.CertPool) {
	t.Helper()
	return startTunnelProxyWithOptions(t, transforms, nil)
}

// startTunnelProxyWithOptions is startTunnelProxy with a hook that adjusts
// the Options before the proxy is built.
func startTunnelProxyWithOptions(t *testing.T, transforms []transform.Transformer, configure func(*Options)) (*Proxy, string, *x509.CertPool) {
	t.Helper()

	caCert, caKey := generateTestCA(t)
	cache, err := certcache.NewFromCA(caCert, caKey, 100, 72*time.Hour)
	require.NoError(t, err)

	pipeline := transform.NewPipeline(transforms, transform.BodyLimits{}, testLogger())
	holder := transform.NewPipelineHolder(pipeline)
	opts := Options{
		HTTPAddr:   "127.0.0.1:0",
		HTTPSAddr:  "127.0.0.1:0",
		TunnelAddr: "127.0.0.1:0",
		CertCache:  cache,
		Pipeline:   holder,
		Logger:     testLogger(),
	}
	if configure != nil {
		configure(&opts)
	}
	p := New(opts)

	// Start tunnel listener
	tunnelLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tunnelAddr := tunnelLn.Addr().String()
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
		tunnelLn.Close()
		close(p.tunnelDone)
	})

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return p, tunnelAddr, pool
}

func TestTunnel_CONNECT_HTTP(t *testing.T) {
	// Start an upstream HTTP server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Tunnel", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from tunnel")
	}))
	defer upstream.Close()

	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	// Send CONNECT request
	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := upstream.Listener.Addr().String()
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	require.NoError(t, err)

	// Read 200 Connection Established
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Now send an HTTP request through the tunnel (raw tunnel, not MITM)
	_, err = fmt.Fprintf(conn, "GET /test HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	require.NoError(t, err)

	resp2, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer resp2.Body.Close()

	require.Equal(t, http.StatusOK, resp2.StatusCode)
	require.Equal(t, "true", resp2.Header.Get("X-Tunnel"))

	body, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from tunnel", string(body))
}

func TestTunnel_CONNECT_HTTPS_MITM(t *testing.T) {
	// Start an upstream HTTPS server
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from tls tunnel")
	}))
	defer upstream.Close()

	p, tunnelAddr, caPool := startTunnelProxy(t, nil)

	// Override transport to route to the upstream
	upstreamAddr := upstream.Listener.Addr().String()
	p.transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}

	const fakeHost = "mitm.example.com"

	// Send CONNECT to port 443 (triggers MITM)
	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", fakeHost, fakeHost)
	require.NoError(t, err)

	// Read 200 Connection Established
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Now do TLS handshake on the tunneled connection
	tlsConn := tls.Client(conn, &tls.Config{
		RootCAs:    caPool,
		ServerName: fakeHost,
	})
	defer func() { _ = tlsConn.Close() }()

	err = tlsConn.Handshake()
	require.NoError(t, err)

	// Send HTTP request through the TLS tunnel
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/test", fakeHost), nil)
	require.NoError(t, err)

	err = req.Write(tlsConn)
	require.NoError(t, err)

	tlsBr := bufio.NewReader(tlsConn)
	resp2, err := http.ReadResponse(tlsBr, req)
	require.NoError(t, err)
	defer resp2.Body.Close()

	require.Equal(t, http.StatusOK, resp2.StatusCode)
	require.False(t, resp2.Close)

	body, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from tls tunnel", string(body))

	req2, err := http.NewRequest("GET", fmt.Sprintf("https://%s/again", fakeHost), nil)
	require.NoError(t, err)

	err = req2.Write(tlsConn)
	require.NoError(t, err)

	resp3, err := http.ReadResponse(tlsBr, req2)
	require.NoError(t, err)
	defer resp3.Body.Close()

	require.Equal(t, http.StatusOK, resp3.StatusCode)
	body, err = io.ReadAll(resp3.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from tls tunnel", string(body))
}

func TestTunnel_HTTPProxyAbsoluteForm(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/test?x=1", r.RequestURI)
		w.Header().Set("X-Tunnel-HTTP", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from http proxy")
	}))
	defer upstream.Close()

	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	proxyURL, err := url.Parse("http://" + tunnelAddr)
	require.NoError(t, err)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport}
	resp, err := client.Get(upstream.URL + "/test?x=1")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "true", resp.Header.Get("X-Tunnel-HTTP"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from http proxy", string(body))
}

func TestTunnel_HTTPProxyRejectsAbsoluteFormHTTPS(t *testing.T) {
	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "GET https://example.com/test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestTunnel_SOCKS5_HTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Socks", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from socks5")
	}))
	defer upstream.Close()

	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	upstreamHost, upstreamPortStr, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	// SOCKS5 auth negotiation: version 5, 1 method (no auth)
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)

	// Read auth response
	authResp := make([]byte, 2)
	_, err = io.ReadFull(conn, authResp)
	require.NoError(t, err)
	require.Equal(t, byte(0x05), authResp[0])
	require.Equal(t, byte(0x00), authResp[1])

	// SOCKS5 connect request: IPv4
	ip := net.ParseIP(upstreamHost).To4()
	require.NotNil(t, ip)

	var port uint16
	_, err = fmt.Sscanf(upstreamPortStr, "%d", &port)
	require.NoError(t, err)

	connectReq := []byte{0x05, 0x01, 0x00, 0x01} // ver, cmd=connect, rsv, atyp=IPv4
	connectReq = append(connectReq, ip...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	connectReq = append(connectReq, portBuf...)

	_, err = conn.Write(connectReq)
	require.NoError(t, err)

	// Read connect response
	connectResp := make([]byte, 10)
	_, err = io.ReadFull(conn, connectResp)
	require.NoError(t, err)
	require.Equal(t, byte(0x05), connectResp[0]) // version
	require.Equal(t, byte(0x00), connectResp[1]) // success

	// Now send HTTP through the tunnel
	target := upstream.Listener.Addr().String()
	_, err = fmt.Fprintf(conn, "GET /test HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "true", resp.Header.Get("X-Socks"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from socks5", string(body))
}

func TestTunnel_SOCKS5_DomainName(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "domain ok")
	}))
	defer upstream.Close()

	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, upstreamPortStr, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	var port uint16
	_, err = fmt.Sscanf(upstreamPortStr, "%d", &port)
	require.NoError(t, err)

	// Auth negotiation
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	authResp := make([]byte, 2)
	_, err = io.ReadFull(conn, authResp)
	require.NoError(t, err)

	// Connect with domain name type (0x03) pointing to 127.0.0.1
	domain := "127.0.0.1" // using IP as "domain" for test simplicity
	connectReq := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	connectReq = append(connectReq, []byte(domain)...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	connectReq = append(connectReq, portBuf...)

	_, err = conn.Write(connectReq)
	require.NoError(t, err)

	connectResp := make([]byte, 10)
	_, err = io.ReadFull(conn, connectResp)
	require.NoError(t, err)
	require.Equal(t, byte(0x00), connectResp[1]) // success

	// Send HTTP request
	target := upstream.Listener.Addr().String()
	_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestTunnel_SOCKS5_NoAuth_Required(t *testing.T) {
	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Offer only username/password auth (0x02), no no-auth
	_, err = conn.Write([]byte{0x05, 0x01, 0x02})
	require.NoError(t, err)

	resp := make([]byte, 2)
	_, err = io.ReadFull(conn, resp)
	require.NoError(t, err)
	require.Equal(t, byte(0x05), resp[0])
	require.Equal(t, byte(0xFF), resp[1]) // no acceptable methods
}

func TestTunnel_TransformReject(t *testing.T) {
	// Use a transform that rejects everything
	rejecter := &rejectTransform{}

	_, tunnelAddr, _ := startTunnelProxy(t, []transform.Transformer{rejecter})

	// Test CONNECT rejection
	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n")
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	_, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	err = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	require.NoError(t, err)
	_, err = br.Peek(1)
	require.ErrorIs(t, err, io.EOF)
}

func TestTunnel_CONNECTHeadersAndRejectResponse(t *testing.T) {
	auth := &connectHeaderAuthTransform{}

	_, tunnelAddr, _ := startTunnelProxy(t, []transform.Transformer{auth})

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
	require.Equal(t, `Basic realm="proxy"`, resp.Header.Get("Proxy-Authenticate"))
	require.Equal(t, "example.com:443", auth.lastTarget)

	conn2, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn2.Close()

	_, err = fmt.Fprintf(conn2, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic ok\r\n\r\n")
	require.NoError(t, err)

	resp2, err := http.ReadResponse(bufio.NewReader(conn2), nil)
	require.NoError(t, err)
	_ = resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)
}

func TestTunnelInfoPropagatesToInnerTransforms(t *testing.T) {
	seen := make(chan *transform.TunnelInfo, 1)
	tunnelInfoTransform := &tunnelInfoTransform{seen: seen}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	_, tunnelAddr, _ := startTunnelProxy(t, []transform.Transformer{tunnelInfoTransform})
	target := upstream.Listener.Addr().String()

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	_, err = fmt.Fprintf(conn, "GET /test HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	require.NoError(t, err)

	resp2, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_ = resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)

	select {
	case info := <-seen:
		require.Equal(t, target, info.Target)
		require.Len(t, info.RequestTransforms, 1)
		require.Equal(t, "tunnel-info", info.RequestTransforms[0].Name)
		require.Equal(t, "alice", info.RequestTransforms[0].Annotations["user_id"])
	case <-time.After(2 * time.Second):
		t.Fatal("inner transform did not receive tunnel info")
	}
}

func TestTunnel_SOCKS5_TransformReject(t *testing.T) {
	rejecter := &rejectTransform{}

	_, tunnelAddr, _ := startTunnelProxy(t, []transform.Transformer{rejecter})

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Auth
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	authResp := make([]byte, 2)
	_, err = io.ReadFull(conn, authResp)
	require.NoError(t, err)

	// Connect to some target
	connectReq := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50} // 127.0.0.1:80
	_, err = conn.Write(connectReq)
	require.NoError(t, err)

	connectResp := make([]byte, 10)
	_, err = io.ReadFull(conn, connectResp)
	require.NoError(t, err)
	require.Equal(t, byte(0x02), connectResp[1]) // connection not allowed
}

// rejectTransform rejects all requests.
type rejectTransform struct{}

func (r *rejectTransform) Name() string { return "rejecter" }

func (r *rejectTransform) TransformRequest(_ context.Context, _ *transform.TransformContext, _ *http.Request) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionReject}, nil
}

func (r *rejectTransform) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

type connectHeaderAuthTransform struct {
	lastTarget string
}

func (c *connectHeaderAuthTransform) Name() string { return "connect-auth" }

func (c *connectHeaderAuthTransform) TransformRequest(_ context.Context, _ *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if req.Method != http.MethodConnect {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	c.lastTarget = req.Host
	if req.Header.Get("Proxy-Authorization") == "Basic ok" {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	return &transform.TransformResult{
		Action: transform.ActionReject,
		Response: &http.Response{
			StatusCode: http.StatusProxyAuthRequired,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Proxy-Authenticate": []string{`Basic realm="proxy"`}},
			Body:       http.NoBody,
		},
	}, nil
}

func (c *connectHeaderAuthTransform) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

type tunnelInfoTransform struct {
	seen chan<- *transform.TunnelInfo
}

func (t *tunnelInfoTransform) Name() string { return "tunnel-info" }

func (t *tunnelInfoTransform) TransformRequest(_ context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if req.Method == http.MethodConnect {
		tctx.Annotate("user_id", "alice")
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	if tctx.Tunnel != nil {
		select {
		case t.seen <- tctx.Tunnel:
		default:
		}
	}
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (t *tunnelInfoTransform) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// dialCONNECT dials the tunnel listener, issues CONNECT for target, and
// returns the connection plus a reader positioned after the 200 reply.
func dialCONNECT(t *testing.T, tunnelAddr, target string) (net.Conn, *bufio.Reader) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return conn, br
}

// dialSOCKS5 dials the tunnel listener and completes a no-auth SOCKS5
// CONNECT to target, which must be an IPv4 host:port.
func dialSOCKS5(t *testing.T, tunnelAddr, target string) (net.Conn, *bufio.Reader) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	targetHost, targetPortStr, err := net.SplitHostPort(target)
	require.NoError(t, err)
	ip := net.ParseIP(targetHost).To4()
	require.NotNil(t, ip)
	var port uint16
	_, err = fmt.Sscanf(targetPortStr, "%d", &port)
	require.NoError(t, err)

	// Auth negotiation: version 5, 1 method (no auth)
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	authResp := make([]byte, 2)
	_, err = io.ReadFull(conn, authResp)
	require.NoError(t, err)
	require.Equal(t, []byte{0x05, 0x00}, authResp)

	connectReq := []byte{0x05, 0x01, 0x00, 0x01} // ver, cmd=connect, rsv, atyp=IPv4
	connectReq = append(connectReq, ip...)
	connectReq = binary.BigEndian.AppendUint16(connectReq, port)
	_, err = conn.Write(connectReq)
	require.NoError(t, err)

	connectResp := make([]byte, 10)
	_, err = io.ReadFull(conn, connectResp)
	require.NoError(t, err)
	require.Equal(t, byte(0x05), connectResp[0]) // version
	require.Equal(t, byte(0x00), connectResp[1]) // success

	return conn, bufio.NewReader(conn)
}

// startWebSocketUpstream starts a raw TCP server that accepts a single
// connection, answers the upgrade request with 101, then hands the
// connection to serve. The connection is closed when serve returns.
func startWebSocketUpstream(t *testing.T, serve func(conn net.Conn, br *bufio.Reader)) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		_, err = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		if err != nil {
			return
		}
		serve(conn, br)
	}()

	return ln.Addr().String()
}

// startWebSocketEchoUpstream is startWebSocketUpstream with an echo loop.
func startWebSocketEchoUpstream(t *testing.T) string {
	t.Helper()
	return startWebSocketUpstream(t, func(conn net.Conn, br *bufio.Reader) {
		_, _ = io.Copy(conn, br)
	})
}

// wsUpgrade sends a WebSocket upgrade request for target over conn and
// verifies the 101 response, leaving br positioned at the relayed stream.
func wsUpgrade(t *testing.T, conn net.Conn, br *bufio.Reader, target string) {
	t.Helper()

	_, err := fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"Sec-WebSocket-Version: 13\r\n\r\n",
		target)
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
}

// wsUpgradeAndEcho upgrades via wsUpgrade, then checks that payload bytes
// echo back.
func wsUpgradeAndEcho(t *testing.T, conn net.Conn, br *bufio.Reader, target string) {
	t.Helper()

	wsUpgrade(t, conn, br, target)

	_, err := conn.Write([]byte("hello websocket"))
	require.NoError(t, err)

	buf := make([]byte, 4096)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, err := br.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "hello websocket", string(buf[:n]))
}

func TestTunnel_CONNECT_WebSocket(t *testing.T) {
	target := startWebSocketEchoUpstream(t)

	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	wsUpgradeAndEcho(t, conn, br, target)
}

func TestTunnel_SOCKS5_WebSocket(t *testing.T) {
	target := startWebSocketEchoUpstream(t)

	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	targetHost, targetPortStr, err := net.SplitHostPort(target)
	require.NoError(t, err)

	// SOCKS5 auth negotiation: version 5, 1 method (no auth)
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)

	authResp := make([]byte, 2)
	_, err = io.ReadFull(conn, authResp)
	require.NoError(t, err)
	require.Equal(t, []byte{0x05, 0x00}, authResp)

	// SOCKS5 connect request: IPv4
	ip := net.ParseIP(targetHost).To4()
	require.NotNil(t, ip)

	var port uint16
	_, err = fmt.Sscanf(targetPortStr, "%d", &port)
	require.NoError(t, err)

	connectReq := []byte{0x05, 0x01, 0x00, 0x01} // ver, cmd=connect, rsv, atyp=IPv4
	connectReq = append(connectReq, ip...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	connectReq = append(connectReq, portBuf...)

	_, err = conn.Write(connectReq)
	require.NoError(t, err)

	connectResp := make([]byte, 10)
	_, err = io.ReadFull(conn, connectResp)
	require.NoError(t, err)
	require.Equal(t, byte(0x05), connectResp[0]) // version
	require.Equal(t, byte(0x00), connectResp[1]) // success

	wsUpgradeAndEcho(t, conn, bufio.NewReader(conn), target)
}

// wsEntryPaths are the ways a client reaches the WebSocket relay with a
// plaintext client connection. Each opens a connection ready for the
// upgrade request to target. The TLS-terminated paths (HTTPS listener,
// CONNECT MITM) are absent: they dial upstream with wss verified against
// system roots, which a test upstream cannot satisfy.
var wsEntryPaths = []struct {
	name string
	open func(t *testing.T, target string) (net.Conn, *bufio.Reader)
}{
	{"http listener", func(t *testing.T, _ string) (net.Conn, *bufio.Reader) {
		_, httpAddr, _, _ := startProxy(t)
		conn, err := net.DialTimeout("tcp", httpAddr, 5*time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		return conn, bufio.NewReader(conn)
	}},
	{"connect tunnel", func(t *testing.T, target string) (net.Conn, *bufio.Reader) {
		_, tunnelAddr, _ := startTunnelProxy(t, nil)
		return dialCONNECT(t, tunnelAddr, target)
	}},
	{"socks5 tunnel", func(t *testing.T, target string) (net.Conn, *bufio.Reader) {
		_, tunnelAddr, _ := startTunnelProxy(t, nil)
		return dialSOCKS5(t, tunnelAddr, target)
	}},
}

// The relay must close the client when the upstream hangs up; the
// pre-fix code only did so for bare *net.TCPConn clients, so tunnelled
// clients hung until they gave up.
func TestWebSocket_UpstreamClosePropagatesToClient(t *testing.T) {
	for _, path := range wsEntryPaths {
		t.Run(path.name, func(t *testing.T) {
			// Upstream hangs up right after the handshake.
			target := startWebSocketUpstream(t, func(net.Conn, *bufio.Reader) {})
			conn, br := path.open(t, target)
			wsUpgrade(t, conn, br, target)

			require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
			_, err := br.ReadByte()
			require.ErrorIs(t, err, io.EOF)
		})
	}
}

// The relay must close the upstream when the client hangs up, or every
// abandoned client leaks an upstream socket.
func TestWebSocket_ClientClosePropagatesToUpstream(t *testing.T) {
	for _, path := range wsEntryPaths {
		t.Run(path.name, func(t *testing.T) {
			upstreamRead := make(chan error, 1)
			target := startWebSocketUpstream(t, func(conn net.Conn, br *bufio.Reader) {
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, err := br.ReadByte()
				upstreamRead <- err
			})
			conn, br := path.open(t, target)
			wsUpgrade(t, conn, br, target)

			require.NoError(t, conn.Close())
			select {
			case err := <-upstreamRead:
				require.ErrorIs(t, err, io.EOF)
			case <-time.After(5 * time.Second):
				t.Fatal("upstream did not observe the client close")
			}
		})
	}
}

// TestServeOneHTTPConn_HijackWaitsForHandler pins the contract that lets
// hijacking handlers (WebSocket relays, CONNECT tunnels) survive their
// callers' deferred conn.Close(): serveOneHTTPConn must not return until a
// hijacking handler has finished with the connection. This covers the TLS
// MITM branch too, which cannot be exercised end-to-end because
// handleWebSocket verifies upstream certificates against system roots.
func TestServeOneHTTPConn_HijackWaitsForHandler(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	release := make(chan struct{})
	serveReturned := make(chan struct{})

	go func() {
		defer close(serveReturned)
		err := serveOneHTTPConn(serverConn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Background HTTP handler: report failures via t.Error.
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("hijacking not supported")
				return
			}
			conn, rw, err := hj.Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			defer conn.Close()
			if _, err := rw.WriteString("HTTP/1.1 101 Switching Protocols\r\n\r\n"); err != nil {
				t.Errorf("write 101: %v", err)
				return
			}
			if err := rw.Flush(); err != nil {
				t.Errorf("flush 101: %v", err)
				return
			}
			<-release
		}))
		if err != nil {
			t.Errorf("serveOneHTTPConn: %v", err)
		}
	}()

	_, err := clientConn.Write([]byte("GET /ws HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	require.NoError(t, err)

	// Read the 101 status line so the hijack has definitely happened.
	br := bufio.NewReader(clientConn)
	statusLine, err := br.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, statusLine, "101")

	select {
	case <-serveReturned:
		t.Fatal("serveOneHTTPConn returned while the hijacking handler was still running")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case <-serveReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("serveOneHTTPConn did not return after the hijacking handler finished")
	}
}

// --- Proxy authentication and browser routes (asm fork) ---

const browserCACommonName = "Agents Secrets Manager Browser CA"

// innerUser is what browserRouteStub observed on a request inside a tunnel
// (or an absolute-form request).
type innerUser struct {
	tunnelUser string
	authUser   string
}

// browserRouteStub stands in for the secrets transform: it approves marked
// CONNECTs to allowed (host:port) and records the user of inner requests.
type browserRouteStub struct {
	allowed string
	inner   chan innerUser
}

func (s *browserRouteStub) Name() string { return "secrets" }

func (s *browserRouteStub) TransformRequest(_ context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if req.Method == http.MethodConnect {
		if req.Header.Get("Asm-Browser-Route") == "1" && req.Host == s.allowed {
			tctx.Annotate("browser_route", "allowed")
		}
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	if s.inner != nil {
		u := innerUser{tunnelUser: tctx.TunnelUser}
		if tctx.Tunnel != nil {
			u.authUser = tctx.Tunnel.AuthUser
		}
		select {
		case s.inner <- u:
		default:
		}
	}
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (s *browserRouteStub) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func requireInnerUser(t *testing.T, ch <-chan innerUser, want innerUser) {
	t.Helper()
	select {
	case got := <-ch:
		require.Equal(t, want, got)
	case <-time.After(2 * time.Second):
		t.Fatal("inner request did not reach the pipeline")
	}
}

// writeProxyAuthFile writes an auth file granting alice/s3cret and
// bob/hunter2 and returns its path.
func writeProxyAuthFile(t *testing.T) string {
	t.Helper()
	return writeAuthFile(t, map[string]string{"bob": "hunter2", "alice": "s3cret"})
}

// writeAuthFile writes an auth file granting each user its password and
// returns its path.
func writeAuthFile(t *testing.T, creds map[string]string) string {
	t.Helper()
	var data []byte
	for user, pass := range creds {
		sum := sha256.Sum256([]byte(pass))
		data = append(data, user+":"+hex.EncodeToString(sum[:])+"\n"...)
	}
	path := filepath.Join(t.TempDir(), "proxy-auth")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

// auditLog collects the audit records a pipeline emits.
type auditLog struct {
	mu      sync.Mutex
	results []transform.PipelineResult
}

// attach registers l as the audit callback of o's pipeline. Call it from a
// startTunnelProxyWithOptions configure hook, before the proxy serves.
func (l *auditLog) attach(o *Options) {
	o.Pipeline.Load().SetAuditFunc(func(r *transform.PipelineResult) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.results = append(l.results, *r)
	})
}

// requireReject waits for a record whose last trace is a traceName reject
// with the given reason, returns it and forgets every record up to it.
func (l *auditLog) requireReject(t *testing.T, traceName, reason string) transform.PipelineResult {
	t.Helper()
	var got transform.PipelineResult
	require.Eventually(t, func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		for i, r := range l.results {
			n := len(r.RequestTransforms)
			if n == 0 {
				continue
			}
			last := r.RequestTransforms[n-1]
			if last.Name == traceName && last.Action == transform.ActionReject && last.Annotations["reason"] == reason {
				got = r
				l.results = l.results[i+1:]
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond, "no %s/%s reject audited", traceName, reason)
	return got
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func basicProxyAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// readUntilClose reads everything the proxy sends before closing.
func readUntilClose(t *testing.T, conn net.Conn, r io.Reader) []byte {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	data, err := io.ReadAll(r)
	if err != nil {
		// Closing with unread client bytes may surface as a reset.
		require.ErrorIs(t, err, syscall.ECONNRESET)
	}
	return data
}

// sendCONNECT dials the tunnel listener and sends CONNECT target with the
// given extra header lines (each ending in \r\n).
func sendCONNECT(t *testing.T, tunnelAddr, target, extraHeaders string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", target, target, extraHeaders)
	require.NoError(t, err)
	return conn, bufio.NewReader(conn)
}

// getThrough sends GET /test for host over an established tunnel and
// returns the response status.
func getThrough(t *testing.T, conn net.Conn, br *bufio.Reader, host string) int {
	t.Helper()
	_, err := fmt.Fprintf(conn, "GET /test HTTP/1.1\r\nHost: %s\r\n\r\n", host)
	require.NoError(t, err)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	return resp.StatusCode
}

// socks5Connect sends a SOCKS5 CONNECT for an IPv4 target after method
// negotiation and requires success.
func socks5Connect(t *testing.T, conn net.Conn, target string) {
	t.Helper()
	targetHost, targetPortStr, err := net.SplitHostPort(target)
	require.NoError(t, err)
	ip := net.ParseIP(targetHost).To4()
	require.NotNil(t, ip)
	port, err := strconv.ParseUint(targetPortStr, 10, 16)
	require.NoError(t, err)

	connectReq := []byte{0x05, 0x01, 0x00, 0x01}
	connectReq = append(connectReq, ip...)
	connectReq = binary.BigEndian.AppendUint16(connectReq, uint16(port))
	_, err = conn.Write(connectReq)
	require.NoError(t, err)

	connectResp := make([]byte, 10)
	_, err = io.ReadFull(conn, connectResp)
	require.NoError(t, err)
	require.Equal(t, byte(0x00), connectResp[1])
}

func startPlainUpstream(t *testing.T) string {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	return upstream.Listener.Addr().String()
}

func TestTunnel_ProxyAuth_CONNECT(t *testing.T) {
	target := startPlainUpstream(t)
	stub := &browserRouteStub{inner: make(chan innerUser, 1)}
	authFile := writeProxyAuthFile(t)
	_, tunnelAddr, _ := startTunnelProxyWithOptions(t, []transform.Transformer{stub}, func(o *Options) {
		o.AuthFile = authFile
	})

	rejected := []struct {
		name   string
		header string
	}{
		{name: "no credentials", header: ""},
		{name: "wrong password", header: "Proxy-Authorization: " + basicProxyAuth("alice", "wrong") + "\r\n"},
		{name: "another user's password", header: "Proxy-Authorization: " + basicProxyAuth("alice", "hunter2") + "\r\n"},
		{name: "unknown user", header: "Proxy-Authorization: " + basicProxyAuth("mallory", "s3cret") + "\r\n"},
		{name: "not basic", header: "Proxy-Authorization: Bearer s3cret\r\n"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			conn, br := sendCONNECT(t, tunnelAddr, target, tc.header)
			require.Equal(t, proxyAuthRequiredResponse, string(readUntilClose(t, conn, br)))
		})
	}

	t.Run("valid credentials", func(t *testing.T) {
		conn, br := sendCONNECT(t, tunnelAddr, target, "Proxy-Authorization: "+basicProxyAuth("alice", "s3cret")+"\r\n")
		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusOK, resp.StatusCode)

		for range 2 {
			require.Equal(t, http.StatusOK, getThrough(t, conn, br, target))
			requireInnerUser(t, stub.inner, innerUser{tunnelUser: "alice", authUser: "alice"})
		}
	})
}

func TestTunnel_ProxyAuth_AbsoluteForm(t *testing.T) {
	target := startPlainUpstream(t)
	stub := &browserRouteStub{inner: make(chan innerUser, 1)}
	authFile := writeProxyAuthFile(t)
	_, tunnelAddr, _ := startTunnelProxyWithOptions(t, []transform.Transformer{stub}, func(o *Options) {
		o.AuthFile = authFile
	})

	send := func(t *testing.T, header string) (net.Conn, *bufio.Reader) {
		conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		_, err = fmt.Fprintf(conn, "GET http://%s/test HTTP/1.1\r\nHost: %s\r\n%s\r\n", target, target, header)
		require.NoError(t, err)
		return conn, bufio.NewReader(conn)
	}

	t.Run("wrong credentials", func(t *testing.T) {
		conn, br := send(t, "Proxy-Authorization: "+basicProxyAuth("alice", "wrong")+"\r\n")
		require.Equal(t, proxyAuthRequiredResponse, string(readUntilClose(t, conn, br)))
	})

	t.Run("no credentials", func(t *testing.T) {
		conn, br := send(t, "")
		require.Equal(t, proxyAuthRequiredResponse, string(readUntilClose(t, conn, br)))
	})

	t.Run("valid credentials", func(t *testing.T) {
		_, br := send(t, "Proxy-Authorization: "+basicProxyAuth("alice", "s3cret")+"\r\n")
		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusOK, resp.StatusCode)
		requireInnerUser(t, stub.inner, innerUser{tunnelUser: "alice"})
	})
}

func TestTunnel_ProxyAuth_SOCKS5(t *testing.T) {
	target := startPlainUpstream(t)
	stub := &browserRouteStub{inner: make(chan innerUser, 1)}
	authFile := writeProxyAuthFile(t)
	_, tunnelAddr, _ := startTunnelProxyWithOptions(t, []transform.Transformer{stub}, func(o *Options) {
		o.AuthFile = authFile
	})

	dial := func(t *testing.T) net.Conn {
		conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}

	t.Run("no-auth method refused", func(t *testing.T) {
		conn := dial(t)
		_, err := conn.Write([]byte{0x05, 0x01, 0x00})
		require.NoError(t, err)
		resp := make([]byte, 2)
		_, err = io.ReadFull(conn, resp)
		require.NoError(t, err)
		require.Equal(t, []byte{0x05, 0xFF}, resp)
	})

	cases := []struct {
		name     string
		user     string
		pass     string
		wantAuth []byte
	}{
		{name: "valid credentials", user: "alice", pass: "s3cret", wantAuth: []byte{0x01, 0x00}},
		{name: "wrong password", user: "alice", pass: "wrong", wantAuth: []byte{0x01, 0x01}},
		{name: "unknown user", user: "mallory", pass: "s3cret", wantAuth: []byte{0x01, 0x01}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := dial(t)
			_, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
			require.NoError(t, err)
			method := make([]byte, 2)
			_, err = io.ReadFull(conn, method)
			require.NoError(t, err)
			require.Equal(t, []byte{0x05, 0x02}, method)

			auth := []byte{0x01, byte(len(tc.user))}
			auth = append(auth, tc.user...)
			auth = append(auth, byte(len(tc.pass)))
			auth = append(auth, tc.pass...)
			_, err = conn.Write(auth)
			require.NoError(t, err)
			authResp := make([]byte, 2)
			_, err = io.ReadFull(conn, authResp)
			require.NoError(t, err)
			require.Equal(t, tc.wantAuth, authResp)

			if tc.wantAuth[1] != 0x00 {
				require.Empty(t, readUntilClose(t, conn, conn))
				return
			}
			socks5Connect(t, conn, target)
			require.Equal(t, http.StatusOK, getThrough(t, conn, bufio.NewReader(conn), target))
			requireInnerUser(t, stub.inner, innerUser{tunnelUser: "alice", authUser: "alice"})
		})
	}
}

func TestTunnel_NoAuthFile_NoTunnelUser(t *testing.T) {
	target := startPlainUpstream(t)
	stub := &browserRouteStub{inner: make(chan innerUser, 1)}
	_, tunnelAddr, _ := startTunnelProxy(t, []transform.Transformer{stub})

	// Credentials are ignored (passed to transforms only) without an auth file.
	conn, br := sendCONNECT(t, tunnelAddr, target, "Proxy-Authorization: "+basicProxyAuth("alice", "wrong")+"\r\n")
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, http.StatusOK, getThrough(t, conn, br, target))
	requireInnerUser(t, stub.inner, innerUser{})
}

// startBrowserRouteProxy starts a tunnel proxy whose browser CA is enabled
// when withBrowserCA is set and returns pools for the root and browser CAs.
func startBrowserRouteProxy(t *testing.T, transforms []transform.Transformer, withBrowserCA bool, configure func(*Options)) (*Proxy, string, *x509.CertPool, *x509.CertPool) {
	t.Helper()
	browserCert, browserKey := generateTestCAWithCN(t, browserCACommonName)
	browserCache, err := certcache.NewFromCA(browserCert, browserKey, 100, 72*time.Hour)
	require.NoError(t, err)
	p, tunnelAddr, rootPool := startTunnelProxyWithOptions(t, transforms, func(o *Options) {
		if withBrowserCA {
			o.BrowserCertCache = browserCache
		}
		if configure != nil {
			configure(o)
		}
	})
	browserPool := x509.NewCertPool()
	browserPool.AddCert(browserCert)
	return p, tunnelAddr, rootPool, browserPool
}

func TestTunnel_BrowserRoute_CONNECTRejected(t *testing.T) {
	stub := &browserRouteStub{allowed: "login.test:443"}
	cases := []struct {
		name          string
		transforms    []transform.Transformer
		withBrowserCA bool
		target        string
		marker        string
		wantMsg       string
	}{
		{name: "invalid marker", transforms: []transform.Transformer{stub}, withBrowserCA: true, target: "login.test:443", marker: "2", wantMsg: msgBrowserRouteMarker},
		{name: "no secrets transform", withBrowserCA: true, target: "login.test:443", marker: "1", wantMsg: msgBrowserRouteNoGrant},
		{name: "host not granted", transforms: []transform.Transformer{stub}, withBrowserCA: true, target: "other.test:443", marker: "1", wantMsg: msgBrowserRouteNoGrant},
		{name: "port not granted", transforms: []transform.Transformer{stub}, withBrowserCA: true, target: "login.test:8443", marker: "1", wantMsg: msgBrowserRouteNoGrant},
		{name: "browser CA not configured", transforms: []transform.Transformer{stub}, target: "login.test:443", marker: "1", wantMsg: msgBrowserRouteDisabled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, tunnelAddr, _, _ := startBrowserRouteProxy(t, tc.transforms, tc.withBrowserCA, nil)
			conn, br := sendCONNECT(t, tunnelAddr, tc.target, "Asm-Browser-Route: "+tc.marker+"\r\n")
			resp, err := http.ReadResponse(br, nil)
			require.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.Equal(t, http.StatusForbidden, resp.StatusCode)
			require.Contains(t, string(body), tc.wantMsg)
			require.Empty(t, readUntilClose(t, conn, br))
		})
	}
}

func TestTunnel_BrowserRoute_Allowed(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Saw-Marker", r.Header.Get("Asm-Browser-Route"))
		_, _ = fmt.Fprint(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	stub := &browserRouteStub{allowed: "login.test:443", inner: make(chan innerUser, 1)}
	authFile := writeProxyAuthFile(t)
	audit := &auditLog{}
	p, tunnelAddr, rootPool, browserPool := startBrowserRouteProxy(t, []transform.Transformer{stub}, true, func(o *Options) {
		o.AuthFile = authFile
		audit.attach(o)
	})
	upstreamAddr := upstream.Listener.Addr().String()
	p.transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}
	creds := "Proxy-Authorization: " + basicProxyAuth("alice", "s3cret") + "\r\n"

	// connect opens an established tunnel to login.test:443.
	connect := func(t *testing.T, headers string) (net.Conn, *bufio.Reader) {
		conn, br := sendCONNECT(t, tunnelAddr, "login.test:443", creds+headers)
		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusOK, resp.StatusCode)
		return conn, br
	}
	handshake := func(t *testing.T, conn net.Conn, br *bufio.Reader, pool *x509.CertPool, serverName string) (*tls.Conn, error) {
		tlsConn := tls.Client(newPeekedConn(conn, br), &tls.Config{RootCAs: pool, ServerName: serverName})
		t.Cleanup(func() { _ = tlsConn.Close() })
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		return tlsConn, tlsConn.Handshake()
	}
	// get sends GET / with the given Host over tlsConn.
	get := func(t *testing.T, tlsConn *tls.Conn, host string) (*http.Response, string) {
		req, err := http.NewRequest(http.MethodGet, "https://login.test/", nil)
		require.NoError(t, err)
		req.Host = host
		req.Header.Set("Asm-Browser-Route", "1")
		require.NoError(t, req.Write(tlsConn))
		resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		return resp, string(body)
	}

	t.Run("browser CA issues the leaf", func(t *testing.T) {
		conn, br := connect(t, "Asm-Browser-Route: 1\r\n")
		tlsConn, err := handshake(t, conn, br, browserPool, "login.test")
		require.NoError(t, err)
		require.Equal(t, browserCACommonName, tlsConn.ConnectionState().PeerCertificates[0].Issuer.CommonName)

		for _, host := range []string{"login.test", "login.test:443"} {
			resp, body := get(t, tlsConn, host)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, "ok", body)
			require.Empty(t, resp.Header.Get("X-Saw-Marker"))
			requireInnerUser(t, stub.inner, innerUser{tunnelUser: "alice", authUser: "alice"})
		}
	})

	t.Run("no marker uses the root CA", func(t *testing.T) {
		conn, br := connect(t, "")
		tlsConn, err := handshake(t, conn, br, rootPool, "login.test")
		require.NoError(t, err)
		require.Equal(t, "Test CA", tlsConn.ConnectionState().PeerCertificates[0].Issuer.CommonName)
	})

	t.Run("SNI mismatch fails the handshake", func(t *testing.T) {
		conn, br := connect(t, "Asm-Browser-Route: 1\r\n")
		_, err := handshake(t, conn, br, browserPool, "other.test")
		require.Error(t, err)
	})

	t.Run("plain HTTP is closed", func(t *testing.T) {
		conn, br := connect(t, "Asm-Browser-Route: 1\r\n")
		_, err := fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: login.test\r\n\r\n")
		require.NoError(t, err)
		require.Empty(t, readUntilClose(t, conn, br))
	})

	t.Run("HTTP/2", func(t *testing.T) {
		conn, br := connect(t, "Asm-Browser-Route: 1\r\n")
		tlsConn := tls.Client(newPeekedConn(conn, br), &tls.Config{
			RootCAs:    browserPool,
			ServerName: "login.test",
			NextProtos: []string{"h2"},
		})
		t.Cleanup(func() { _ = tlsConn.Close() })
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		require.NoError(t, tlsConn.Handshake())
		require.Equal(t, "h2", tlsConn.ConnectionState().NegotiatedProtocol)
		cc, err := (&http2.Transport{}).NewClientConn(tlsConn)
		require.NoError(t, err)

		cases := []struct {
			name       string
			authority  string
			wantStatus int
			wantBody   string
		}{
			{name: "matching authority", authority: "login.test", wantStatus: http.StatusOK, wantBody: "ok"},
			{name: "authority mismatch", authority: "other.test", wantStatus: http.StatusMisdirectedRequest, wantBody: msgBrowserRouteAuthority + "\n"},
			{name: "port mismatch", authority: "login.test:8443", wantStatus: http.StatusMisdirectedRequest, wantBody: msgBrowserRouteAuthority + "\n"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				req, err := http.NewRequest(http.MethodGet, "https://login.test/", nil)
				require.NoError(t, err)
				req.Host = tc.authority
				resp, err := cc.RoundTrip(req)
				require.NoError(t, err)
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				require.NoError(t, resp.Body.Close())
				require.Equal(t, 2, resp.ProtoMajor)
				require.Equal(t, tc.wantStatus, resp.StatusCode)
				require.Equal(t, tc.wantBody, string(body))
				if tc.wantStatus == http.StatusOK {
					requireInnerUser(t, stub.inner, innerUser{tunnelUser: "alice", authUser: "alice"})
					return
				}
				got := audit.requireReject(t, browserRouteTrace, "authority_mismatch")
				require.Equal(t, tc.authority, got.Host)
			})
		}
	})

	authorityCases := []struct {
		name string
		host string
	}{
		{name: "other port", host: "login.test:8443"},
		{name: "other host", host: "other.test"},
		{name: "other host default port", host: "other.test:443"},
	}
	for _, tc := range authorityCases {
		t.Run("inner authority mismatch/"+tc.name, func(t *testing.T) {
			conn, br := connect(t, "Asm-Browser-Route: 1\r\n")
			tlsConn, err := handshake(t, conn, br, browserPool, "login.test")
			require.NoError(t, err)
			resp, body := get(t, tlsConn, tc.host)
			require.Equal(t, http.StatusMisdirectedRequest, resp.StatusCode)
			require.Contains(t, body, msgBrowserRouteAuthority)

			got := audit.requireReject(t, browserRouteTrace, "authority_mismatch")
			require.Equal(t, http.StatusMisdirectedRequest, got.StatusCode)
			require.Equal(t, tc.host, got.Host)
			require.Equal(t, "login.test", got.SNI)
			require.NotNil(t, got.Tunnel)
			require.Equal(t, "alice", got.Tunnel.AuthUser)
		})
	}
}

func TestBrowserRouteMarkerOutsideCONNECT(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		_, _ = fmt.Fprint(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	target := upstream.Listener.Addr().String()
	p, tunnelAddr, _ := startTunnelProxy(t, nil)

	t.Run("absolute-form", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		_, err = fmt.Fprintf(conn, "GET http://%s/test HTTP/1.1\r\nHost: %s\r\nAsm-Browser-Route: 1\r\n\r\n", target, target)
		require.NoError(t, err)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		require.Contains(t, string(body), msgBrowserRouteMarker)
	})

	t.Run("direct", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://"+target+"/test", nil)
		req.Header.Set("Asm-Browser-Route", "1")
		rec := httptest.NewRecorder()
		p.handleDirectHTTP(rec, req)
		require.Equal(t, http.StatusForbidden, rec.Code)
		require.Contains(t, rec.Body.String(), msgBrowserRouteMarker)
	})

	require.Zero(t, upstreamHits.Load())
}

// TestTunnel_EarlyRejectsAreAudited pins that refusals made before any
// pipeline run (proxy auth, invalid marker) still emit an audit record and a
// log line, and that neither carries the offered credentials.
func TestTunnel_EarlyRejectsAreAudited(t *testing.T) {
	const badPass = "wrong-Pa55word"
	audit := &auditLog{}
	logs := &syncBuffer{}
	authFile := writeProxyAuthFile(t)
	_, tunnelAddr, _ := startTunnelProxyWithOptions(t, nil, func(o *Options) {
		o.AuthFile = authFile
		o.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
		audit.attach(o)
	})
	badAuth := "Proxy-Authorization: " + basicProxyAuth("alice", badPass) + "\r\n"

	dial := func(t *testing.T) net.Conn {
		conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	expect407 := func(t *testing.T, conn net.Conn, br *bufio.Reader) {
		require.Equal(t, proxyAuthRequiredResponse, string(readUntilClose(t, conn, br)))
	}

	cases := []struct {
		name       string
		do         func(t *testing.T)
		wantStatus int
		wantTrace  string
		wantReason string
		wantHost   string
		wantMethod string
	}{
		{
			name: "CONNECT without credentials",
			do: func(t *testing.T) {
				conn, br := sendCONNECT(t, tunnelAddr, "login.test:443", "")
				expect407(t, conn, br)
			},
			wantStatus: http.StatusProxyAuthRequired, wantTrace: proxyAuthTrace, wantReason: "missing_credentials",
			wantHost: "login.test:443", wantMethod: http.MethodConnect,
		},
		{
			name: "CONNECT with wrong credentials",
			do: func(t *testing.T) {
				conn, br := sendCONNECT(t, tunnelAddr, "login.test:443", badAuth)
				expect407(t, conn, br)
			},
			wantStatus: http.StatusProxyAuthRequired, wantTrace: proxyAuthTrace, wantReason: "invalid_credentials",
			wantHost: "login.test:443", wantMethod: http.MethodConnect,
		},
		{
			name: "absolute-form with wrong credentials",
			do: func(t *testing.T) {
				conn := dial(t)
				_, err := fmt.Fprintf(conn, "GET http://example.test/x HTTP/1.1\r\nHost: example.test\r\n%s\r\n", badAuth)
				require.NoError(t, err)
				expect407(t, conn, bufio.NewReader(conn))
			},
			wantStatus: http.StatusProxyAuthRequired, wantTrace: proxyAuthTrace, wantReason: "invalid_credentials",
			wantHost: "example.test", wantMethod: http.MethodGet,
		},
		{
			name: "CONNECT with invalid browser route marker",
			do: func(t *testing.T) {
				conn, br := sendCONNECT(t, tunnelAddr, "login.test:443", "Asm-Browser-Route: 2\r\n"+badAuth)
				resp, err := http.ReadResponse(br, nil)
				require.NoError(t, err)
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				require.NoError(t, resp.Body.Close())
				require.Equal(t, msgBrowserRouteMarker+"\n", string(body))
				require.Equal(t, http.StatusForbidden, resp.StatusCode)
				require.Empty(t, readUntilClose(t, conn, br))
			},
			wantStatus: http.StatusForbidden, wantTrace: browserRouteTrace, wantReason: "invalid_marker",
			wantHost: "login.test:443", wantMethod: http.MethodConnect,
		},
		{
			name: "SOCKS5 with wrong credentials",
			do: func(t *testing.T) {
				conn := dial(t)
				_, err := conn.Write([]byte{0x05, 0x01, 0x02})
				require.NoError(t, err)
				method := make([]byte, 2)
				_, err = io.ReadFull(conn, method)
				require.NoError(t, err)
				require.Equal(t, []byte{0x05, 0x02}, method)
				auth := append([]byte{0x01, byte(len("alice"))}, "alice"...)
				auth = append(append(auth, byte(len(badPass))), badPass...)
				_, err = conn.Write(auth)
				require.NoError(t, err)
				require.Equal(t, []byte{0x01, 0x01}, readUntilClose(t, conn, conn))
			},
			wantStatus: http.StatusProxyAuthRequired, wantTrace: proxyAuthTrace, wantReason: "invalid_credentials",
			wantMethod: http.MethodConnect,
		},
		{
			name: "SOCKS5 without username/password method",
			do: func(t *testing.T) {
				conn := dial(t)
				_, err := conn.Write([]byte{0x05, 0x01, 0x00})
				require.NoError(t, err)
				require.Equal(t, []byte{0x05, 0xFF, 0x00, 0x01, 0, 0, 0, 0, 0, 0}, readUntilClose(t, conn, conn))
			},
			wantStatus: http.StatusProxyAuthRequired, wantTrace: proxyAuthTrace, wantReason: "missing_credentials",
			wantMethod: http.MethodConnect,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.do(t)
			got := audit.requireReject(t, tc.wantTrace, tc.wantReason)
			require.Equal(t, transform.ActionReject, got.Action)
			require.Equal(t, tc.wantStatus, got.StatusCode)
			require.Equal(t, tc.wantHost, got.Host)
			require.Equal(t, tc.wantMethod, got.Method)
			require.NotEmpty(t, got.RemoteAddr)
			require.NotContains(t, fmt.Sprintf("%+v", got), badPass)
		})
	}

	out := logs.String()
	require.Contains(t, out, "request rejected by proxy")
	require.Contains(t, out, "rejected_by=proxy_auth")
	require.Contains(t, out, "rejected_by=browser_route")
	require.NotContains(t, out, badPass)
	require.NotContains(t, out, basicProxyAuth("alice", badPass)[len("Basic "):])
}

// TestTunnel_SNIOnly_TunnelUser pins that the passthrough request of an
// authenticated tunnel in sni-only mode carries the tunnel user.
func TestTunnel_SNIOnly_TunnelUser(t *testing.T) {
	stub := &browserRouteStub{inner: make(chan innerUser, 1)}
	authFile := writeProxyAuthFile(t)
	p, tunnelAddr, _ := startTunnelProxyWithOptions(t, []transform.Transformer{stub}, func(o *Options) {
		o.TLSMode = "sni-only"
		o.AuthFile = authFile
	})
	// Nothing listens here; the upstream dial fails after the pipeline ran.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, closedPort, err := net.SplitHostPort(closed.Addr().String())
	require.NoError(t, err)
	require.NoError(t, closed.Close())
	p.sniUpstreamPort = closedPort

	conn, br := sendCONNECT(t, tunnelAddr, "localhost:443", "Proxy-Authorization: "+basicProxyAuth("alice", "s3cret")+"\r\n")
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	tlsConn := tls.Client(newPeekedConn(conn, br), &tls.Config{ServerName: "localhost", InsecureSkipVerify: true})
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	require.Error(t, tlsConn.Handshake())
	requireInnerUser(t, stub.inner, innerUser{tunnelUser: "alice"})
}
