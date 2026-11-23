package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckCredentials(t *testing.T) {
	authFile := writeProxyAuthFile(t)
	upperSum := sha256.Sum256([]byte("Upper"))
	upperFile := filepath.Join(t.TempDir(), "proxy-auth")
	require.NoError(t, os.WriteFile(upperFile, []byte("carol:"+strings.ToUpper(hex.EncodeToString(upperSum[:]))+"\nmalformed\nnohex:zz\n"), 0o600))

	cases := []struct {
		name     string
		authFile string
		user     string
		pass     string
		want     bool
	}{
		{name: "valid", authFile: authFile, user: "alice", pass: "s3cret", want: true},
		{name: "second user", authFile: authFile, user: "bob", pass: "hunter2", want: true},
		{name: "wrong password", authFile: authFile, user: "alice", pass: "hunter2", want: false},
		{name: "unknown user", authFile: authFile, user: "mallory", pass: "s3cret", want: false},
		{name: "empty user", authFile: authFile, user: "", pass: "s3cret", want: false},
		{name: "uppercase hex with malformed lines", authFile: upperFile, user: "carol", pass: "Upper", want: true},
		{name: "malformed line", authFile: upperFile, user: "malformed", pass: "", want: false},
		{name: "missing file", authFile: filepath.Join(t.TempDir(), "absent"), user: "alice", pass: "s3cret", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Proxy{authFile: tc.authFile, logger: testLogger()}
			require.True(t, p.authRequired())
			require.Equal(t, tc.want, p.checkCredentials(tc.user, tc.pass))
		})
	}
}

func TestCheckCredentials_RereadsFile(t *testing.T) {
	authFile := writeProxyAuthFile(t)
	p := &Proxy{authFile: authFile, logger: testLogger()}
	require.True(t, p.checkCredentials("alice", "s3cret"))

	require.NoError(t, os.WriteFile(authFile, []byte(""), 0o600))
	require.False(t, p.checkCredentials("alice", "s3cret"))
}

func TestAuthUser(t *testing.T) {
	p := &Proxy{authFile: writeProxyAuthFile(t), logger: testLogger()}

	cases := []struct {
		name     string
		header   string
		wantUser string
		wantOK   bool
	}{
		{name: "valid", header: basicProxyAuth("alice", "s3cret"), wantUser: "alice", wantOK: true},
		{name: "lowercase scheme", header: "basic " + strings.TrimPrefix(basicProxyAuth("bob", "hunter2"), "Basic "), wantUser: "bob", wantOK: true},
		{name: "wrong password", header: basicProxyAuth("alice", "nope")},
		{name: "missing header", header: ""},
		{name: "bearer", header: "Bearer s3cret"},
		{name: "bad base64", header: "Basic !!!"},
		{name: "no colon", header: "Basic YWxpY2U="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.header != "" {
				h.Set("Proxy-Authorization", tc.header)
			}
			user, ok := p.authUser(h)
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantUser, user)
		})
	}
}

func TestProxyAuthDisabled(t *testing.T) {
	require.False(t, (&Proxy{}).authRequired())
}
