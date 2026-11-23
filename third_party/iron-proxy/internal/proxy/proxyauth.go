package proxy

// Proxy authentication (asm fork). When an auth file is configured, the
// tunnel listener requires credentials: Basic Proxy-Authorization on CONNECT
// and absolute-form requests, RFC 1929 username/password on SOCKS5. The
// authenticated user becomes TransformContext.TunnelUser for every request
// the connection carries. The HTTP/HTTPS listeners are not covered.

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
)

// proxyAuthRequiredResponse is written verbatim before closing the
// connection when a tunnel-listener request lacks valid credentials.
const proxyAuthRequiredResponse = "HTTP/1.1 407 Proxy Authentication Required\r\n" +
	"Proxy-Authenticate: Basic realm=\"asm\"\r\n" +
	"Content-Length: 0\r\n" +
	"Connection: close\r\n\r\n"

// proxyAuthTrace names the audit trace of a proxy-authentication refusal.
const proxyAuthTrace = "proxy_auth"

// errSOCKS5AuthFailed is returned by socks5Authenticate for wrong credentials.
var errSOCKS5AuthFailed = errors.New("socks5 authentication failed")

// proxyAuthReason is the audit reason for a refused Proxy-Authorization
// header. It never includes the credentials.
func proxyAuthReason(h http.Header) string {
	if h.Get("Proxy-Authorization") == "" {
		return "missing_credentials"
	}
	return "invalid_credentials"
}

// authRequired reports whether the tunnel listener requires credentials.
func (p *Proxy) authRequired() bool {
	return p.authFile != ""
}

// checkCredentials reports whether user and pass match a line of the auth
// file. The file is re-read on every call so the manager can rotate
// credentials without a restart. Lines are "<user>:<hex sha256(pass)>"; a
// missing or unreadable file denies everyone.
func (p *Proxy) checkCredentials(user, pass string) bool {
	if user == "" {
		return false
	}
	data, err := os.ReadFile(p.authFile)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			p.logger.Warn("reading proxy auth file", slog.String("error", err.Error()))
		}
		return false
	}
	sum := sha256.Sum256([]byte(pass))
	ok := false
	for _, line := range strings.Split(string(data), "\n") {
		name, hexHash, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found || name != user {
			continue
		}
		want, err := hex.DecodeString(hexHash)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare(want, sum[:]) == 1 {
			ok = true
		}
	}
	return ok
}

// authUser returns the user of a valid Basic Proxy-Authorization header.
func (p *Proxy) authUser(h http.Header) (string, bool) {
	scheme, encoded, found := strings.Cut(h.Get("Proxy-Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", false
	}
	user, pass, found := strings.Cut(string(decoded), ":")
	if !found || !p.checkCredentials(user, pass) {
		return "", false
	}
	return user, true
}

// writeProxyAuthRequired answers 407 with proxyAuthRequiredResponse and
// closes the connection.
func (p *Proxy) writeProxyAuthRequired(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		w.Header().Set("Proxy-Authenticate", `Basic realm="asm"`)
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		p.logger.Warn("proxy auth hijack error", slog.String("error", err.Error()))
		return
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, proxyAuthRequiredResponse); err != nil {
		p.logger.Debug("proxy auth write 407 error", slog.String("error", err.Error()))
	}
}

// socks5Authenticate runs the RFC 1929 username/password sub-negotiation
// after the server selected method 0x02. It replies 01 00 on success and
// 01 01 on failure; on failure the caller closes the connection.
func (p *Proxy) socks5Authenticate(conn net.Conn, br *bufio.Reader) (string, error) {
	ver, err := br.ReadByte()
	if err != nil {
		return "", fmt.Errorf("read auth version: %w", err)
	}
	user, err := readSOCKS5Field(br)
	if err != nil {
		return "", fmt.Errorf("read username: %w", err)
	}
	pass, err := readSOCKS5Field(br)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if ver != 0x01 || !p.checkCredentials(user, pass) {
		if _, err := conn.Write([]byte{0x01, 0x01}); err != nil {
			return "", fmt.Errorf("write auth failure: %w", err)
		}
		return "", errSOCKS5AuthFailed
	}
	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		return "", fmt.Errorf("write auth success: %w", err)
	}
	return user, nil
}

// readSOCKS5Field reads a length-prefixed RFC 1929 field.
func readSOCKS5Field(br *bufio.Reader) (string, error) {
	n, err := br.ReadByte()
	if err != nil {
		return "", err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(br, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}
