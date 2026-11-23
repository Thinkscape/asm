package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/config"
	"github.com/ironsh/iron-proxy/internal/transform"
	"golang.org/x/net/http2"
)

// listenTunnel starts the CONNECT/SOCKS5 tunnel listener.
func (p *Proxy) listenTunnel() error {
	ln, err := net.Listen("tcp", p.tunnelAddr)
	if err != nil {
		return fmt.Errorf("tunnel listen: %w", err)
	}
	p.tunnelListener = ln
	p.logger.Info("tunnel proxy starting", slog.String("addr", ln.Addr().String()))

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-p.tunnelDone:
				return nil
			default:
			}
			p.logger.Warn("tunnel accept error", slog.String("error", err.Error()))
			continue
		}
		go p.handleTunnel(conn)
	}
}

// handleTunnel peeks at the first byte to dispatch to HTTP proxy or SOCKS5.
// This is the single logging point for tunnel connection errors.
func (p *Proxy) handleTunnel(conn net.Conn) {
	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		p.logger.Debug("tunnel peek error", slog.String("error", err.Error()))
		conn.Close()
		return
	}

	// SOCKS5 starts with version byte 0x05
	if first[0] == 0x05 {
		if err := p.handleSOCKS5(conn, br); err != nil {
			p.logger.Debug("tunnel socks5 error", slog.String("error", err.Error()))
		}
		return
	}

	// Otherwise assume HTTP proxy traffic. This supports both CONNECT and
	// absolute-form HTTP requests on the same explicit proxy port.
	if err := p.serveTunnelProxyHTTP(newPeekedConn(conn, br)); err != nil {
		p.logger.Debug("tunnel http error", slog.String("error", err.Error()))
	}
}

// serveTunnelProxyHTTP serves HTTP proxy requests on the tunnel listener.
// CONNECT establishes a tunnel; all other methods are forwarded through the
// normal HTTP proxy path.
func (p *Proxy) serveTunnelProxyHTTP(conn net.Conn) error {
	return serveOneHTTPConn(conn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			p.handleTunnelCONNECT(w, r)
			return
		}
		var user string
		if p.authRequired() {
			u, ok := p.authUser(r.Header)
			if !ok {
				p.rejectEarly(&transform.PipelineResult{
					Host:       r.Host,
					Method:     r.Method,
					Path:       r.URL.Path,
					RemoteAddr: r.RemoteAddr,
					Mode:       transform.ModeMITM,
				}, http.StatusProxyAuthRequired, proxyAuthTrace, proxyAuthReason(r.Header))
				p.writeProxyAuthRequired(w)
				return
			}
			user = u
		}
		if r.URL.Scheme != "http" {
			http.Error(w, "unsupported proxy request scheme", http.StatusBadRequest)
			return
		}
		p.handleHTTP(w, r, nil, user)
	}))
}

// Browser routes (asm fork): a CONNECT carrying "Asm-Browser-Route: 1" asks
// for a leaf signed by the browser CA. It is issued only when the pipeline's
// secrets transform approved the (host, port) pair for browser routing.
const (
	browserRouteHeader = "Asm-Browser-Route"
	browserRouteTrace  = "browser_route"

	msgBrowserRouteMarker    = "asm: invalid browser route marker"
	msgBrowserRouteDisabled  = "asm: browser routing is not enabled on this manager"
	msgBrowserRouteNoGrant   = "asm: no active login grant routes this host through asm"
	msgBrowserRouteAuthority = "asm: request authority does not match the browser route"
)

// handleTunnelCONNECT handles HTTP CONNECT tunnel requests.
func (p *Proxy) handleTunnelCONNECT(w http.ResponseWriter, req *http.Request) {
	host := req.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}

	p.logger.Debug("tunnel CONNECT", slog.String("target", host))

	// preflight is the audit record for a CONNECT refused before the
	// pipeline runs.
	hostname, _, _ := net.SplitHostPort(host)
	preflight := &transform.PipelineResult{
		Host:       host,
		Method:     http.MethodConnect,
		RemoteAddr: req.RemoteAddr,
		SNI:        hostname,
		Mode:       p.tunnelMode(),
	}

	marker := req.Header.Get(browserRouteHeader)
	browser := marker == "1"
	if marker != "" && !browser {
		p.rejectEarly(preflight, http.StatusForbidden, browserRouteTrace, "invalid_marker")
		w.Header().Set("Connection", "close")
		p.writeResponse(w, textResponse(http.StatusForbidden, msgBrowserRouteMarker))
		return
	}

	var authUser string
	if p.authRequired() {
		user, ok := p.authUser(req.Header)
		if !ok {
			p.rejectEarly(preflight, http.StatusProxyAuthRequired, proxyAuthTrace, proxyAuthReason(req.Header))
			p.writeProxyAuthRequired(w)
			return
		}
		authUser = user
	}

	ok, rejectResp, tunnelInfo := p.tunnelTransformCheck(req.RemoteAddr, host, req.Header, authUser, browser)
	if !ok {
		w.Header().Set("Connection", "close")
		if rejectResp == nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		p.writeResponse(w, rejectResp)
		return
	}
	cache := p.certCache
	if browser {
		cache = p.browserCertCache
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		p.logger.Warn("tunnel hijack error", slog.String("error", err.Error()))
		return
	}
	defer conn.Close()

	// Send 200 to signal tunnel established.
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		p.logger.Warn("tunnel write 200 error", slog.String("error", err.Error()))
		return
	}
	if err := rw.Flush(); err != nil {
		p.logger.Warn("tunnel flush 200 error", slog.String("error", err.Error()))
		return
	}

	if err := p.serveTunnelWithReader(conn, rw.Reader, host, tunnelInfo, cache, browser); err != nil {
		p.logger.Debug("tunnel connect error", slog.String("error", err.Error()))
	}
}

// handleSOCKS5 handles SOCKS5 tunnel requests.
func (p *Proxy) handleSOCKS5(conn net.Conn, br *bufio.Reader) error {
	defer conn.Close()

	// --- Auth negotiation ---
	ver, err := br.ReadByte()
	if err != nil {
		return fmt.Errorf("read version: %w", err)
	}
	if ver != 0x05 {
		return fmt.Errorf("unsupported socks version: %d", ver)
	}

	nmethods, err := br.ReadByte()
	if err != nil {
		return fmt.Errorf("read nmethods: %w", err)
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}

	var authUser string
	if p.authRequired() {
		// preflight is the audit record for a SOCKS5 handshake refused
		// before the target is known.
		preflight := &transform.PipelineResult{
			Method:     http.MethodConnect,
			RemoteAddr: conn.RemoteAddr().String(),
			Mode:       p.tunnelMode(),
		}
		// Only username/password (RFC 1929) is acceptable.
		if !slices.Contains(methods, 0x02) {
			p.rejectEarly(preflight, http.StatusProxyAuthRequired, proxyAuthTrace, "missing_credentials")
			if err := p.socks5Reply(conn, 0xFF); err != nil {
				return fmt.Errorf("write no-acceptable-methods: %w", err)
			}
			return nil
		}
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			return fmt.Errorf("write auth reply: %w", err)
		}
		user, err := p.socks5Authenticate(conn, br)
		if errors.Is(err, errSOCKS5AuthFailed) {
			p.rejectEarly(preflight, http.StatusProxyAuthRequired, proxyAuthTrace, "invalid_credentials")
		}
		if err != nil {
			return err
		}
		authUser = user
	} else {
		// Without an auth file only no-auth (0x00) is supported.
		if !slices.Contains(methods, 0x00) {
			if err := p.socks5Reply(conn, 0xFF); err != nil {
				return fmt.Errorf("write no-acceptable-methods: %w", err)
			}
			return nil
		}
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return fmt.Errorf("write auth reply: %w", err)
		}
	}

	// --- Connect request ---
	header := make([]byte, 4)
	if _, err := io.ReadFull(br, header); err != nil {
		return fmt.Errorf("read connect header: %w", err)
	}
	if header[0] != 0x05 {
		return fmt.Errorf("unexpected socks version in connect: %d", header[0])
	}
	if header[1] != 0x01 { // only CONNECT supported
		if err := p.socks5Reply(conn, 0x07); err != nil {
			return fmt.Errorf("write command-not-supported: %w", err)
		}
		return nil
	}

	var targetHost string
	atyp := header[3]
	switch atyp {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(br, addr); err != nil {
			return fmt.Errorf("read ipv4 addr: %w", err)
		}
		targetHost = net.IP(addr).String()
	case 0x03: // Domain name
		domainLen, err := br.ReadByte()
		if err != nil {
			return fmt.Errorf("read domain length: %w", err)
		}
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(br, domain); err != nil {
			return fmt.Errorf("read domain: %w", err)
		}
		targetHost = string(domain)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(br, addr); err != nil {
			return fmt.Errorf("read ipv6 addr: %w", err)
		}
		targetHost = net.IP(addr).String()
	default:
		if err := p.socks5Reply(conn, 0x08); err != nil {
			return fmt.Errorf("write address-type-not-supported: %w", err)
		}
		return nil
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)
	target := net.JoinHostPort(targetHost, strconv.Itoa(int(port)))

	p.logger.Debug("tunnel SOCKS5 CONNECT", slog.String("target", target))

	ok, _, tunnelInfo := p.tunnelTransformCheck(conn.RemoteAddr().String(), target, nil, authUser, false)
	if !ok {
		if err := p.socks5Reply(conn, 0x02); err != nil {
			return fmt.Errorf("write connection-not-allowed: %w", err)
		}
		return nil
	}

	// Success reply
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(reply); err != nil {
		return fmt.Errorf("write success reply: %w", err)
	}

	return p.serveTunnel(conn, target, tunnelInfo)
}

// socks5Reply sends a SOCKS5 reply with the given status code.
func (p *Proxy) socks5Reply(conn net.Conn, status byte) error {
	reply := []byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(reply)
	return err
}

// tunnelTransformCheck runs a synthetic CONNECT request through the transform
// pipeline to decide whether the tunnel should be allowed. When connectHeaders
// is non-nil the headers from the original CONNECT request (e.g.
// Proxy-Authorization) are forwarded to transforms so they can make
// authentication and policy decisions at the tunnel level. authUser is the
// proxy-authenticated user ("" when proxy auth is off); it becomes the
// tunnel's AuthUser. When browser is set, the tunnel is additionally denied
// unless browser routing is enabled and the secrets transform annotated the
// CONNECT with browser_route=allowed.
func (p *Proxy) tunnelTransformCheck(remoteAddr, target string, connectHeaders http.Header, authUser string, browser bool) (bool, *http.Response, *transform.TunnelInfo) {
	host, _, _ := net.SplitHostPort(target)

	hdr := http.Header{}
	if connectHeaders != nil {
		hdr = connectHeaders.Clone()
	}

	req := &http.Request{
		Method:     http.MethodConnect,
		Host:       target,
		URL:        &url.URL{Host: target},
		Header:     hdr,
		RemoteAddr: remoteAddr,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	req.Body = transform.NewBufferedBody(http.NoBody, 0)

	mode := p.tunnelMode()

	tctx := &transform.TransformContext{
		Logger:     p.logger,
		SNI:        host,
		Mode:       mode,
		TunnelUser: authUser,
	}

	result := &transform.PipelineResult{
		Host:       target,
		Method:     http.MethodConnect,
		Path:       "",
		RemoteAddr: remoteAddr,
		SNI:        host,
		Mode:       mode,
	}
	pl, finish := p.beginPipelineRun(result)
	defer finish()

	if !p.isReady() {
		markNotReady(result)
		return false, notReadyResponse(), nil
	}

	rejectResp, err := pl.ProcessRequest(req.Context(), tctx, req, &result.RequestTransforms)
	if err != nil {
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusBadGateway
		result.Err = err
		p.logger.Warn("tunnel transform error",
			slog.String("target", target),
			slog.String("error", err.Error()),
		)
		return false, nil, nil
	}
	if rejectResp != nil {
		result.Action = transform.ShortCircuitAction(result.RequestTransforms)
		result.StatusCode = rejectResp.StatusCode
		p.logger.Info("tunnel short-circuited by transform",
			slog.String("target", target),
			slog.Int("status", rejectResp.StatusCode),
		)
		return false, rejectResp, nil
	}

	if browser {
		if reason, msg := p.browserRouteDenial(result.RequestTransforms); msg != "" {
			markReject(result, http.StatusForbidden, browserRouteTrace, reason)
			p.logger.Info("browser route denied",
				slog.String("target", target),
				slog.String("reason", reason),
			)
			return false, textResponse(http.StatusForbidden, msg), nil
		}
	}

	result.Action = transform.ActionContinue
	result.StatusCode = http.StatusOK
	return true, nil, &transform.TunnelInfo{
		Target:            target,
		RequestTransforms: result.RequestTransforms,
		AuthUser:          authUser,
	}
}

// browserRouteDenial reports why a marked CONNECT may not use the browser CA,
// or "" when it may: browser routing must be configured and the secrets
// transform must have annotated the CONNECT with browser_route=allowed. With
// no secrets transform nothing is allowed.
func (p *Proxy) browserRouteDenial(traces []transform.TransformTrace) (reason, msg string) {
	if p.browserCertCache == nil {
		return "browser_routing_disabled", msgBrowserRouteDisabled
	}
	for _, tr := range traces {
		if tr.Name == "secrets" && tr.Annotations["browser_route"] == "allowed" {
			return "", ""
		}
	}
	return "no_login_grant", msgBrowserRouteNoGrant
}

// textResponse builds a synthetic plain-text response carrying msg.
func textResponse(status int, msg string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     strconv.Itoa(status) + " " + http.StatusText(status),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(msg + "\n")),
	}
}

// tunnelMode is the transform mode of CONNECT/SOCKS5 tunnel requests.
func (p *Proxy) tunnelMode() transform.Mode {
	if p.tlsMode == config.TLSModeSNIOnly {
		return transform.ModeSNIOnly
	}
	return transform.ModeMITM
}

// markReject records on result that the proxy itself (not a transform)
// refused the request, as a reject trace named traceName.
func markReject(result *transform.PipelineResult, status int, traceName, reason string) {
	result.Action = transform.ActionReject
	result.StatusCode = status
	result.RequestTransforms = append(result.RequestTransforms, transform.TransformTrace{
		Name:        traceName,
		Action:      transform.ActionReject,
		Annotations: map[string]any{"reason": reason},
	})
}

// rejectEarly audits and logs a request refused before any pipeline run
// (proxy authentication, browser route checks). result must never carry
// credentials.
func (p *Proxy) rejectEarly(result *transform.PipelineResult, status int, traceName, reason string) {
	_, finish := p.beginPipelineRun(result)
	markReject(result, status, traceName, reason)
	finish()
	p.logger.Info("request rejected by proxy",
		slog.String("host", result.Host),
		slog.String("method", result.Method),
		slog.String("remote_addr", result.RemoteAddr),
		slog.String("rejected_by", traceName),
		slog.String("reason", reason),
		slog.Int("status", status),
	)
}

// serveTunnel peeks at the client's first byte after the SOCKS5 handshake to
// detect TLS (0x16) vs plain HTTP. TLS connections get MITM'd with the root
// CA; plain HTTP is served directly through handleHTTP. Anything else is
// rejected.
func (p *Proxy) serveTunnel(clientConn net.Conn, target string, tunnelInfo *transform.TunnelInfo) error {
	br := bufio.NewReader(clientConn)
	return p.serveTunnelWithReader(clientConn, br, target, tunnelInfo, p.certCache, false)
}

// serveTunnelWithReader dispatches on the client's first byte. cache signs
// MITM leaves; browser restricts the tunnel to TLS for exactly target.
func (p *Proxy) serveTunnelWithReader(clientConn net.Conn, br *bufio.Reader, target string, tunnelInfo *transform.TunnelInfo, cache *certcache.Cache, browser bool) error {
	first, err := br.Peek(1)
	if err != nil {
		return fmt.Errorf("peek client protocol: %w", err)
	}

	// Wrap the conn so the peeked byte is not lost.
	peekedConn := newPeekedConn(clientConn, br)

	if first[0] == 0x16 {
		// TLS ClientHello: MITM
		return p.serveTunnelTLS(peekedConn, target, tunnelInfo, cache, browser)
	}

	if browser {
		return fmt.Errorf("browser route %s: non-TLS first byte 0x%02x", target, first[0])
	}

	if isHTTPMethodByte(first[0]) {
		// Plain HTTP request
		return p.serveTunnelHTTP(peekedConn, target, tunnelInfo)
	}

	return fmt.Errorf("unsupported protocol (first byte 0x%02x) for target %s", first[0], target)
}

// serveTunnelTLS handles the TLS branch of a tunnel connection. In MITM mode
// it terminates TLS with a leaf from cache and serves HTTP via handleHTTP; in
// sni-only mode it peeks SNI and TCP-passthroughs to the SNI host on port 443
// (the CONNECT port is ignored to prevent port-pivot attacks). For a browser
// route the SNI and every inner request's authority must match target.
func (p *Proxy) serveTunnelTLS(clientConn net.Conn, target string, tunnelInfo *transform.TunnelInfo, cache *certcache.Cache, browser bool) error {
	if p.tlsMode == config.TLSModeSNIOnly {
		return p.serveSNIPassthrough(clientConn, tunnelInfo.AuthUser)
	}

	targetHost, targetPort := splitAuthority(target, "443")
	tlsConn := tls.Server(clientConn, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if browser && !strings.EqualFold(hello.ServerName, targetHost) {
				return nil, fmt.Errorf("browser route %s: SNI %q does not match", target, hello.ServerName)
			}
			return issueLeaf(cache, hello)
		},
		NextProtos: []string{"h2", "http/1.1"}, // offer HTTP/2 to tunnelled clients
	})
	defer func() { _ = tlsConn.Close() }()

	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		return fmt.Errorf("TLS handshake for %s: %w", target, err)
	}

	user := tunnelInfo.AuthUser
	return serveOneHTTPConn(tlsConn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if browser {
			host, port := splitAuthority(r.Host, "443")
			if !strings.EqualFold(host, targetHost) || port != targetPort {
				p.rejectEarly(&transform.PipelineResult{
					Host:       r.Host,
					Method:     r.Method,
					Path:       r.URL.Path,
					RemoteAddr: r.RemoteAddr,
					SNI:        r.TLS.ServerName,
					Mode:       transform.ModeMITM,
					Tunnel:     cloneTunnelInfo(tunnelInfo),
				}, http.StatusMisdirectedRequest, browserRouteTrace, "authority_mismatch")
				http.Error(w, msgBrowserRouteAuthority, http.StatusMisdirectedRequest)
				return
			}
		}
		p.handleHTTP(w, r, tunnelInfo, user)
	}))
}

// serveTunnelHTTP serves plain HTTP requests through the normal handleHTTP handler.
func (p *Proxy) serveTunnelHTTP(clientConn net.Conn, target string, tunnelInfo *transform.TunnelInfo) error {
	defer clientConn.Close()

	return serveOneHTTPConn(clientConn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.handleHTTP(w, r, tunnelInfo, tunnelInfo.AuthUser)
	}))
}

// splitAuthority splits a host[:port] authority, using defaultPort when the
// port is absent and stripping IPv6 brackets.
func splitAuthority(authority, defaultPort string) (host, port string) {
	if h, p, err := net.SplitHostPort(authority); err == nil {
		return h, p
	}
	return strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]"), defaultPort
}

func serveOneHTTPConn(conn net.Conn, handler http.Handler) error {
	ln := newOneConnListener(conn)
	var hijacked atomic.Bool
	var handlers sync.WaitGroup
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlers.Add(1)
			defer handlers.Done()
			handler.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       10 * time.Second,
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateHijacked {
				hijacked.Store(true)
			}
			if state == http.StateClosed || state == http.StateHijacked {
				ln.closeDone()
			}
		},
	}
	// Serve HTTP/2 when a tunnelled conn negotiates it; zero config never errors.
	_ = http2.ConfigureServer(srv, &http2.Server{})
	err := srv.Serve(ln)
	// A hijacking handler (WebSocket relay, CONNECT tunnel) owns the
	// connection until it returns. Serve comes back as soon as the hijack
	// happens, so wait for the handler before returning: callers defer
	// Close on the connection and must not run it mid-relay.
	if hijacked.Load() {
		handlers.Wait()
	}
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func cloneTunnelInfo(info *transform.TunnelInfo) *transform.TunnelInfo {
	if info == nil {
		return nil
	}
	traces := slices.Clone(info.RequestTransforms)
	for i := range traces {
		traces[i].Annotations = maps.Clone(traces[i].Annotations)
	}
	return &transform.TunnelInfo{
		Target:            info.Target,
		RequestTransforms: traces,
		AuthUser:          info.AuthUser,
	}
}

// isHTTPMethodByte returns true if b could be the first byte of an HTTP method.
func isHTTPMethodByte(b byte) bool {
	// HTTP methods start with uppercase ASCII: GET, HEAD, POST, PUT, DELETE,
	// CONNECT, OPTIONS, TRACE, PATCH
	return b >= 'A' && b <= 'Z'
}

// oneConnListener is a net.Listener that returns a single connection, then
// blocks until Close is called. This lets us serve a single hijacked
// connection using http.Server.Serve.
type oneConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func newOneConnListener(conn net.Conn) *oneConnListener {
	return &oneConnListener{
		conn: conn,
		done: make(chan struct{}),
	}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error {
	l.closeDone()
	return nil
}

func (l *oneConnListener) closeDone() {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
}

func (l *oneConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// peekedConn wraps a net.Conn with a bufio.Reader so that bytes consumed
// by Peek are still available for subsequent reads.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func newPeekedConn(conn net.Conn, r *bufio.Reader) *peekedConn {
	return &peekedConn{Conn: conn, r: r}
}

func (c *peekedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}
