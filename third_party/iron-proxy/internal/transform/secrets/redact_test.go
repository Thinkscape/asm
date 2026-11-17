package secrets

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

const (
	openaiSentinel = "proxy-openai-abc123"
	openaiReal     = "sk-real-openai-key"
)

// allHeadersEntry is a replace entry for OPENAI_API_KEY scanning every header
// and the body.
func allHeadersEntry() secretEntry {
	return secretEntry{
		Source:  envSource("OPENAI_API_KEY"),
		Rules:   []hostmatch.RuleConfig{{Host: "api.openai.com"}},
		Replace: &replaceConfig{ProxyValue: openaiSentinel, MatchBody: true},
	}
}

// swapRequest runs TransformRequest on an HTTPS request to api.openai.com
// carrying the sentinel in X-Key (unless sentinel is false) and returns the
// shared TransformContext.
func swapRequest(t *testing.T, s *Secrets, sentinel bool) (*http.Request, *transform.TransformContext) {
	t.Helper()
	req := openaiReq("GET", "/v1/echo")
	if sentinel {
		req.Header.Set("X-Key", openaiSentinel)
	}
	tctx := &transform.TransformContext{}
	res, err := s.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	return req, tctx
}

func upstreamResponse(body io.Reader, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        header,
		Body:          transform.NewBufferedBody(io.NopCloser(body), 0),
		ContentLength: -1,
	}
}

// respond runs TransformResponse and returns the result plus the full body.
func respond(t *testing.T, s *Secrets, tctx *transform.TransformContext, req *http.Request, resp *http.Response) (*transform.TransformResult, string) {
	t.Helper()
	res, err := s.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)
	out := resp
	if res.Response != nil {
		out = res.Response
	}
	body, err := io.ReadAll(out.Body)
	require.NoError(t, err)
	return res, string(body)
}

func TestSecrets_SecondBodySecretSwapped(t *testing.T) {
	s := makeSecrets(t, []secretEntry{
		{
			Source:  envSource("OPENAI_API_KEY"),
			Rules:   []hostmatch.RuleConfig{{Host: "api.example.com"}},
			Replace: &replaceConfig{ProxyValue: "proxy-first-token", MatchBody: true},
		},
		{
			Source:  envSource("INTERNAL_TOKEN"),
			Rules:   []hostmatch.RuleConfig{{Host: "api.example.com"}},
			Replace: &replaceConfig{ProxyValue: "proxy-second-token", MatchBody: true},
		},
	})

	req := httptest.NewRequest("POST", "https://api.example.com/v1", nil)
	req.Host = "api.example.com"
	req.Body = transform.NewBufferedBody(io.NopCloser(strings.NewReader(`{"k":"proxy-second-token"}`)), 1<<20)

	doTransform(t, s, req)

	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, `{"k":"real-internal-token"}`, string(body))
}

func TestSecrets_TruncatedBodyNotSwapped(t *testing.T) {
	s := makeSecrets(t, []secretEntry{allHeadersEntry()})

	body := openaiSentinel + strings.Repeat("x", 100)
	req := openaiReq("POST", "/v1/chat")
	rb := transform.NewBufferedBody(io.NopCloser(strings.NewReader(body)), 50)
	req.Body = rb

	doTransform(t, s, req)

	require.True(t, rb.Truncated())
	require.Same(t, rb, req.Body)
}

func TestSecrets_WebSocketUpgradeWithSentinelRejected(t *testing.T) {
	s := makeSecrets(t, []secretEntry{allHeadersEntry()})

	req := openaiReq("GET", "/v1/realtime")
	req.Header.Set("Connection", "keep-alive, Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Authorization", "Bearer "+openaiSentinel)

	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
	require.Equal(t, http.StatusForbidden, res.Response.StatusCode)
	body, err := io.ReadAll(res.Response.Body)
	require.NoError(t, err)
	require.Equal(t, "asm: sentinels are not substituted on WebSocket upgrades\n", string(body))
}

func TestSecrets_WebSocketUpgradeWithoutSentinelAllowed(t *testing.T) {
	s := makeSecrets(t, []secretEntry{allHeadersEntry()})

	req := openaiReq("GET", "/v1/realtime")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	doTransform(t, s, req)
}

func TestSecrets_RequestHeadersStripped(t *testing.T) {
	cases := []struct {
		name          string
		sentinel      bool
		wantRangeGone bool
	}{
		{"with substitution", true, true},
		{"without substitution", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := makeSecrets(t, []secretEntry{allHeadersEntry()})
			req := openaiReq("GET", "/v1/file")
			req.Header.Set("Accept-Encoding", "gzip, br")
			req.Header.Set("Range", "bytes=0-10")
			req.Header.Set("If-Range", `"etag"`)
			if tc.sentinel {
				req.Header.Set("X-Key", openaiSentinel)
			}

			doTransform(t, s, req)

			require.Empty(t, req.Header.Values("Accept-Encoding"))
			if tc.wantRangeGone {
				require.Empty(t, req.Header.Get("Range"))
				require.Empty(t, req.Header.Get("If-Range"))
			} else {
				require.Equal(t, "bytes=0-10", req.Header.Get("Range"))
			}
		})
	}
}

func TestSecrets_AcceptEncodingKeptWithoutReplaceEntries(t *testing.T) {
	s := makeSecrets(t, []secretEntry{injectEntry()})
	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Accept-Encoding", "gzip")

	doTransform(t, s, req)

	require.Equal(t, "gzip", req.Header.Get("Accept-Encoding"))
}

func TestSecrets_RedactBodyEcho(t *testing.T) {
	cases := []struct {
		name   string
		reader func(string) io.Reader
	}{
		{"single read", func(s string) io.Reader { return strings.NewReader(s) }},
		{"one byte per read", func(s string) io.Reader { return iotest.OneByteReader(strings.NewReader(s)) }},
		{"split inside value", func(s string) io.Reader {
			cut := strings.Index(s, openaiReal) + len(openaiReal)/2
			return &chunkReader{chunks: []string{s[:cut], s[cut:]}}
		}},
		{"half reads", func(s string) io.Reader { return iotest.HalfReader(strings.NewReader(s)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := makeSecrets(t, []secretEntry{allHeadersEntry()})
			req, tctx := swapRequest(t, s, true)
			require.Equal(t, openaiReal, req.Header.Get("X-Key"))

			resp := upstreamResponse(tc.reader(`{"echo":"`+openaiReal+`","again":"`+openaiReal+`"}`), http.Header{"Content-Length": {"60"}})
			res, body := respond(t, s, tctx, req, resp)

			require.Equal(t, transform.ActionContinue, res.Action)
			require.Equal(t, `{"echo":"`+openaiSentinel+`","again":"`+openaiSentinel+`"}`, body)
			require.Empty(t, resp.Header.Get("Content-Length"))
			require.Equal(t, int64(-1), resp.ContentLength)
		})
	}
}

// chunkReader returns one chunk per Read call.
type chunkReader struct{ chunks []string }

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.chunks[0])
	c.chunks[0] = c.chunks[0][n:]
	if c.chunks[0] == "" {
		c.chunks = c.chunks[1:]
	}
	return n, nil
}

func TestSecrets_RedactEncodedForms(t *testing.T) {
	// A value whose encodings differ from the raw form.
	const real = "s3cr3t/value+with=chars&<>"
	const sentinel = "asm_sentinelABCDEFGH"
	registry := sourceBuilderRegistry{"env": &fakeBuilder{secrets: map[string]string{"ODD": real}}}
	s, err := newFromConfig(secretsConfig{Secrets: []secretEntry{{
		Source:  envSource("ODD"),
		Rules:   []hostmatch.RuleConfig{{Host: "api.openai.com"}},
		Replace: &replaceConfig{ProxyValue: sentinel},
	}}}, registry)
	require.NoError(t, err)

	cases := []struct {
		name   string
		encode func(string) string
	}{
		{"raw", func(v string) string { return v }},
		{"query escape", url.QueryEscape},
		{"path escape", url.PathEscape},
		{"json", func(v string) string { return jsonEscape(v, true) }},
		{"json without html escaping", func(v string) string { return jsonEscape(v, false) }},
		{"json escaped slash", func(v string) string { return strings.ReplaceAll(jsonEscape(v, true), "/", `\/`) }},
		{"base64 std", func(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) }},
		{"base64 url", func(v string) string { return base64.URLEncoding.EncodeToString([]byte(v)) }},
		{"hex", func(v string) string { return hex.EncodeToString([]byte(v)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := openaiReq("GET", "/v1/echo")
			req.Header.Set("X-Key", sentinel)
			tctx := &transform.TransformContext{}
			_, err := s.TransformRequest(context.Background(), tctx, req)
			require.NoError(t, err)
			require.Equal(t, real, req.Header.Get("X-Key"))

			encoded := tc.encode(real)
			_, body := respond(t, s, tctx, req, upstreamResponse(strings.NewReader("<"+encoded+">"), nil))

			require.Equal(t, "<"+tc.encode(sentinel)+">", body)
			require.NotContains(t, body, encoded)
		})
	}
}

func TestSecrets_RedactBasicAuthEcho(t *testing.T) {
	s := makeSecrets(t, []secretEntry{allHeadersEntry()})

	req := openaiReq("GET", "/v1/echo")
	req.SetBasicAuth("alice", openaiSentinel)
	sentPayload := strings.TrimPrefix(req.Header.Get("Authorization"), "Basic ")
	tctx := &transform.TransformContext{}
	_, err := s.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	realPayload := strings.TrimPrefix(req.Header.Get("Authorization"), "Basic ")
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("alice:"+openaiReal)), realPayload)

	_, body := respond(t, s, tctx, req, upstreamResponse(strings.NewReader(`{"authorization":"Basic `+realPayload+`"}`), nil))

	require.Equal(t, `{"authorization":"Basic `+sentPayload+`"}`, body)
}

func TestSecrets_RedactHeadersAndTrailers(t *testing.T) {
	s := makeSecrets(t, []secretEntry{allHeadersEntry()})
	req, tctx := swapRequest(t, s, true)

	resp := upstreamResponse(strings.NewReader("ok"), http.Header{
		"X-Echo":   {"token=" + openaiReal},
		"Location": {"https://example.com/?k=" + url.QueryEscape(openaiReal)},
	})
	resp.Trailer = http.Header{"X-Trailer-Echo": {openaiReal}}
	_, body := respond(t, s, tctx, req, resp)

	require.Equal(t, "ok", body)
	require.Equal(t, "token="+openaiSentinel, resp.Header.Get("X-Echo"))
	require.Equal(t, "https://example.com/?k="+openaiSentinel, resp.Header.Get("Location"))
	require.Equal(t, openaiSentinel, resp.Trailer.Get("X-Trailer-Echo"))
}

func TestSecrets_RedactOtherEntryValue(t *testing.T) {
	s := makeSecrets(t, []secretEntry{
		allHeadersEntry(),
		{
			Source:  envSource("INTERNAL_TOKEN"),
			Rules:   []hostmatch.RuleConfig{{Host: "internal.example.com"}},
			Replace: &replaceConfig{ProxyValue: "proxy-internal-token"},
		},
	})
	// No substitution in this request at all.
	req, tctx := swapRequest(t, s, false)
	require.Empty(t, tctx.RedactPairs)

	_, body := respond(t, s, tctx, req, upstreamResponse(strings.NewReader("a=real-internal-token b="+openaiReal), nil))

	require.Equal(t, "a=asm_redacted b=asm_redacted", body)
}

func TestSecrets_RedactSkipsShortValues(t *testing.T) {
	registry := sourceBuilderRegistry{"env": &fakeBuilder{secrets: map[string]string{"SHORT": "abc1234"}}}
	s, err := newFromConfig(secretsConfig{Secrets: []secretEntry{{
		Source:  envSource("SHORT"),
		Rules:   []hostmatch.RuleConfig{{Host: "api.openai.com"}},
		Replace: &replaceConfig{ProxyValue: "proxy-short-sentinel"},
	}}}, registry)
	require.NoError(t, err)

	req := openaiReq("GET", "/v1/echo")
	req.Header.Set("X-Key", "proxy-short-sentinel")
	tctx := &transform.TransformContext{}
	_, err = s.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, "abc1234", req.Header.Get("X-Key"))

	_, body := respond(t, s, tctx, req, upstreamResponse(strings.NewReader("echo abc1234"), nil))
	require.Equal(t, "echo abc1234", body)
}

func TestSecrets_ContentEncodedResponse(t *testing.T) {
	cases := []struct {
		name       string
		sentinel   bool
		method     string
		status     int
		wantReject bool
	}{
		{"after swap", true, "GET", http.StatusOK, true},
		{"after swap, HEAD", true, "HEAD", http.StatusOK, false},
		{"after swap, 304", true, "GET", http.StatusNotModified, false},
		{"without swap", false, "GET", http.StatusOK, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := makeSecrets(t, []secretEntry{allHeadersEntry()})
			req := openaiReq(tc.method, "/v1/echo")
			if tc.sentinel {
				req.Header.Set("X-Key", openaiSentinel)
			}
			tctx := &transform.TransformContext{}
			_, err := s.TransformRequest(context.Background(), tctx, req)
			require.NoError(t, err)

			const encoded = "\x1f\x8b-not-really-gzip"
			resp := upstreamResponse(strings.NewReader(encoded), http.Header{"Content-Encoding": {"gzip"}, "Content-Length": {"18"}})
			resp.StatusCode = tc.status
			res, body := respond(t, s, tctx, req, resp)

			if tc.wantReject {
				require.Equal(t, transform.ActionReject, res.Action)
				require.Equal(t, http.StatusBadGateway, res.Response.StatusCode)
				require.Equal(t, "asm: upstream response is content-encoded; refusing to forward unredacted\n", body)
				return
			}
			require.Equal(t, transform.ActionContinue, res.Action)
			require.Equal(t, encoded, body)
			require.Equal(t, "18", resp.Header.Get("Content-Length"))
		})
	}
}

func TestSecrets_ResponseUntouchedWithoutReplaceEntries(t *testing.T) {
	s := makeSecrets(t, []secretEntry{injectEntry()})
	req := openaiReq("GET", "/v1/chat")
	resp := upstreamResponse(strings.NewReader("sk-real-openai-key"), http.Header{"Content-Length": {"18"}})
	resp.ContentLength = 18

	res, body := respond(t, s, &transform.TransformContext{}, req, resp)

	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "sk-real-openai-key", body)
	require.Equal(t, int64(18), resp.ContentLength)
}

func TestRedactor_PrefersLongestAndCompletesStraddlingMatch(t *testing.T) {
	r := newRedactor([]needle{
		{old: []byte("abcdefghij"), new: []byte("<long>")},
		{old: []byte("ghijXYZW12"), new: []byte("<other>")},
		{old: []byte("abcdefgh"), new: []byte("<short>")},
	})
	// Feed byte by byte so every split point is exercised.
	rr := newRedactReader(iotest.OneByteReader(strings.NewReader("..abcdefghij..ghijXYZW12..abcdefghZ")), r, func() {})
	out, err := io.ReadAll(rr)
	require.NoError(t, err)
	require.Equal(t, "..<long>..<other>..<short>Z", string(out))
}

const endedSentinel = "asm_endedendedendedendedendedendedended0000"

// endedEntry is the config of an expired or revoked lease's sentinel.
func endedEntry() secretEntry {
	return secretEntry{Replace: &replaceConfig{ProxyValue: endedSentinel, Ended: true}}
}

func TestSecrets_EndedSentinelRejected(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		prepare func(req *http.Request)
	}{
		{"header to formerly approved host", "https://api.openai.com/v1/chat", func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer "+endedSentinel)
		}},
		{"header to other host", "https://evil.com/steal", func(req *http.Request) {
			req.Header.Set("X-Key", endedSentinel)
		}},
		{"basic auth", "https://api.openai.com/v1/chat", func(req *http.Request) {
			req.SetBasicAuth("user", endedSentinel)
		}},
		{"path", "https://api.openai.com/v1/" + endedSentinel, func(*http.Request) {}},
		{"query", "https://api.openai.com/v1/chat?k=" + endedSentinel, func(*http.Request) {}},
		{"plain http", "http://api.openai.com/v1/chat", func(req *http.Request) {
			req.Header.Set("X-Key", endedSentinel)
		}},
		{"next to an active sentinel", "https://api.openai.com/v1/chat", func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer "+openaiSentinel)
			req.Header.Set("X-Old", endedSentinel)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := makeSecrets(t, []secretEntry{allHeadersEntry(), endedEntry()})
			req := httptest.NewRequest("GET", tc.url, nil)
			tc.prepare(req)

			tctx := &transform.TransformContext{}
			res, err := s.TransformRequest(context.Background(), tctx, req)
			require.NoError(t, err)
			require.Equal(t, transform.ActionReject, res.Action)
			require.Equal(t, http.StatusForbidden, res.Response.StatusCode)
			body, err := io.ReadAll(res.Response.Body)
			require.NoError(t, err)
			require.Equal(t, "asm: sentinel expired or revoked; run asm get again\n", string(body))
			require.Equal(t, "sentinel_ended", tctx.DrainAnnotations()["reject_reason"])
			require.NotContains(t, req.Header.Get("Authorization"), openaiReal)
		})
	}
}

func TestSecrets_EndedSentinelOutsideScannedPlacesPasses(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(req *http.Request)
	}{
		{"no sentinel", func(*http.Request) {}},
		{"only in body", func(req *http.Request) {
			body := `{"key":"` + endedSentinel + `"}`
			req.Body = transform.NewBufferedBody(io.NopCloser(strings.NewReader(body)), 1<<20)
		}},
		{"active sentinel only", func(req *http.Request) {
			req.Header.Set("X-Key", openaiSentinel)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := makeSecrets(t, []secretEntry{allHeadersEntry(), endedEntry()})
			req := openaiReq("POST", "/v1/chat")
			tc.prepare(req)
			doTransform(t, s, req)
			require.NotEqual(t, openaiSentinel, req.Header.Get("X-Key"))
		})
	}
}

func TestSecrets_EndedEntryConfig(t *testing.T) {
	cases := []struct {
		name   string
		yaml   string
		errMsg string
	}{
		{"no source or rules", `secrets: [{replace: {proxy_value: "asm_x", ended: true}}]`, ""},
		{"with source", `secrets: [{source: {type: env, var: X}, replace: {proxy_value: "asm_x", ended: true}}]`, "an ended entry takes no source or rules"},
		{"with rules", `secrets: [{rules: [{host: "a.example.com"}], replace: {proxy_value: "asm_x", ended: true}}]`, "an ended entry takes no source or rules"},
		{"without proxy_value", `secrets: [{replace: {ended: true}}]`, "replace.proxy_value is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc yaml.Node
			require.NoError(t, yaml.Unmarshal([]byte(tc.yaml), &doc))
			tr, err := factory(*doc.Content[0], slog.Default())
			if tc.errMsg != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errMsg)
				return
			}
			require.NoError(t, err)
			require.Equal(t, []string{"asm_x"}, tr.(*Secrets).ended)
			require.Empty(t, tr.(*Secrets).secrets)
		})
	}
}

func TestSecrets_EndedEntriesAreNotRedactionNeedles(t *testing.T) {
	s := makeSecrets(t, []secretEntry{endedEntry()})
	req := openaiReq("GET", "/v1/chat")
	req.Header.Set("Accept-Encoding", "gzip")
	tctx := &transform.TransformContext{}
	res, err := s.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "gzip", req.Header.Get("Accept-Encoding"), "an ended entry never substitutes")

	payload := "echo " + endedSentinel
	resp := upstreamResponse(strings.NewReader(payload), http.Header{"Content-Length": {"48"}})
	resp.ContentLength = int64(len(payload))
	res, body := respond(t, s, tctx, req, resp)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, payload, body)
	require.Equal(t, int64(len(payload)), resp.ContentLength)
}
