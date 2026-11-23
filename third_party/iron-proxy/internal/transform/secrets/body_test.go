package secrets

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
)

func TestRequestBodyKind(t *testing.T) {
	cases := []struct {
		contentType string
		want        bodyKind
	}{
		{"application/x-www-form-urlencoded", bodyForm},
		{"Application/X-WWW-Form-Urlencoded; charset=UTF-8", bodyForm},
		{"application/json", bodyJSON},
		{"application/json; charset=utf-8", bodyJSON},
		{"application/problem+json", bodyJSON},
		{"multipart/form-data; boundary=x", bodyMultipart},
		{"text/plain", bodyOther},
		{"", bodyOther},
		{"not a media type;;", bodyOther},
	}
	for _, tc := range cases {
		t.Run(tc.contentType, func(t *testing.T) {
			req := httptest.NewRequest("POST", "https://example.com/", nil)
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			require.Equal(t, tc.want, requestBodyKind(req))
		})
	}
}

func TestScannableBody(t *testing.T) {
	const body = "user=a&password=b"
	cases := []struct {
		name          string
		maxBytes      int64
		contentLength int64
		contentType   string
		encoding      string
		plainBody     bool
		wantOK        bool
	}{
		{"known length within limit", 1 << 20, int64(len(body)), "text/plain", "", false, true},
		{"known length unlimited", 0, int64(len(body)), "text/plain", "", false, true},
		{"identity encoding", 1 << 20, int64(len(body)), "text/plain", "identity", false, true},
		{"declared over limit", 4, int64(len(body)), "application/x-www-form-urlencoded", "", false, false},
		{"unknown length form", 1 << 20, -1, "application/x-www-form-urlencoded", "", false, true},
		{"unknown length json", 1 << 20, -1, "application/json", "", false, true},
		{"unknown length other", 1 << 20, -1, "text/plain", "", false, false},
		{"unknown length form truncated", 4, -1, "application/x-www-form-urlencoded", "", false, false},
		{"gzip", 1 << 20, int64(len(body)), "application/x-www-form-urlencoded", "gzip", false, false},
		{"identity then gzip", 1 << 20, int64(len(body)), "application/x-www-form-urlencoded", "identity, gzip", false, false},
		{"not a buffered body", 1 << 20, int64(len(body)), "application/x-www-form-urlencoded", "", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "https://example.com/", nil)
			if tc.plainBody {
				req.Body = io.NopCloser(strings.NewReader(body))
			} else {
				req.Body = transform.NewBufferedBody(io.NopCloser(strings.NewReader(body)), tc.maxBytes)
			}
			req.ContentLength = tc.contentLength
			req.Header.Set("Content-Type", tc.contentType)
			if tc.encoding != "" {
				req.Header.Set("Content-Encoding", tc.encoding)
			}

			data, ok, err := scannableBody(req)
			require.NoError(t, err)
			require.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				require.Equal(t, body, string(data))
				// The body is rewound for the next reader.
				again, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				require.Equal(t, body, string(again))
			} else {
				require.Nil(t, data)
			}
		})
	}

	t.Run("nil body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "https://example.com/", nil)
		req.Body = nil
		data, ok, err := scannableBody(req)
		require.NoError(t, err)
		require.False(t, ok)
		require.Nil(t, data)
	})
}

func TestSecrets_UnreadableBodyRejected(t *testing.T) {
	s := makeSecrets(t, []secretEntry{defaultEntry()})
	req := openaiReq("POST", "/v1/chat")
	req.Body = transform.NewBufferedBody(io.NopCloser(iotest.ErrReader(errors.New("client went away"))), 1<<20)
	req.ContentLength = 10

	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
	require.Equal(t, http.StatusBadRequest, res.Response.StatusCode)
	msg, err := io.ReadAll(res.Response.Body)
	require.NoError(t, err)
	require.Equal(t, msgBodyUnreadable+"\n", string(msg))
}

func TestEscapeReal(t *testing.T) {
	const real = `p&ss="x\y</b>` + "\n"
	cases := []struct {
		kind bodyKind
		want string
	}{
		{bodyForm, `p%26ss%3D%22x%5Cy%3C%2Fb%3E%0A`},
		{bodyJSON, `p&ss=\"x\\y</b>\n`},
		{bodyMultipart, real},
		{bodyOther, real},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, escapeReal(tc.kind, real))
	}
}

const (
	swapSentinel = "asm_login_0123456789abcdef"
	swapReal     = `p&ss="x\y`
)

func TestSwapLoginForm(t *testing.T) {
	s := swapSentinel
	cases := []struct {
		name   string
		body   string
		want   string
		wantOK bool
	}{
		{"last field", "user=a&password=" + s, "user=a&password=p%26ss%3D%22x%5Cy", true},
		{"first field, others byte-identical", "password=" + s + "&next=%2Fhome+page&flag", "password=p%26ss%3D%22x%5Cy&next=%2Fhome+page&flag", true},
		{"escaped name kept raw", "pass%5Bword%5D=" + s, "pass%5Bword%5D=p%26ss%3D%22x%5Cy", true},
		{"sentinel as name", s + "=x", "", false},
		{"sentinel as bare name", "a=b&" + s, "", false},
		{"inside a longer value", "password=x" + s, "", false},
		{"twice", "password=" + s + "&confirm=" + s, "", false},
		{"twice, once escaped", "password=" + s + "&confirm=%61" + s[1:], "", false},
		{"only escaped", "password=%61" + s[1:], "", false},
		{"undecodable segment", "password=" + s + "%zz", "", false},
		{"absent", "user=a", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := swapLoginForm([]byte(tc.body), s, swapReal)
			require.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				require.Equal(t, tc.want, string(got))
			}
		})
	}
}

func TestSwapLoginJSON(t *testing.T) {
	s := swapSentinel
	cases := []struct {
		name   string
		body   string
		want   string
		wantOK bool
	}{
		{"nested value", `{"user":{"pw":"` + s + `"}}`, `{"user":{"pw":"p&ss=\"x\\y"}}`, true},
		{"top-level string", `"` + s + `"`, `"p&ss=\"x\\y"`, true},
		{"array element, whitespace kept", `{"a": [1, true, null, "` + s + `" ], "b": 2.50}`, `{"a": [1, true, null, "p&ss=\"x\\y" ], "b": 2.50}`, true},
		{"value after nested object", `{"o":{"k":"v"},"pw":"` + s + `"}`, `{"o":{"k":"v"},"pw":"p&ss=\"x\\y"}`, true},
		{"key", `{"` + s + `":"x"}`, "", false},
		{"nested key", `{"a":[{"` + s + `":1}]}`, "", false},
		{"inside a longer value", `{"pw":"x` + s + `"}`, "", false},
		{"twice", `{"pw":"` + s + `","c":"` + s + `"}`, "", false},
		{"escaped and raw", `{"pw":"` + s + `","c":"\u0061` + s[1:] + `"}`, "", false},
		{"two top-level values", `{"pw":"` + s + `"} {}`, "", false},
		{"trailing garbage", `{"pw":"` + s + `"} x`, "", false},
		{"truncated", `{"pw":"` + s + `"`, "", false},
		{"absent", `{"pw":"x"}`, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := swapLoginJSON([]byte(tc.body), s, swapReal)
			require.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				require.Equal(t, tc.want, string(got))
			}
		})
	}
}
