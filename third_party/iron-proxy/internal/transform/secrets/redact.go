package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/ironsh/iron-proxy/internal/transform"
)

const (
	// redactedPlaceholder replaces echoes of real values that this request
	// did not substitute. It is never another entry's sentinel, so a response
	// cannot hand one client a placeholder that works for someone else.
	redactedPlaceholder = "asm_redacted"

	// minNeedleLen drops short needles: they would match ordinary content
	// and corrupt responses far more often than they would catch a leak.
	minNeedleLen = 8

	msgEncodedResponse = "asm: upstream response is content-encoded; refusing to forward unredacted"
)

// TransformResponse redacts echoes of real secret values from response
// headers, trailers and the body. Values substituted into this request are
// replaced by the placeholder the client sent; values of every other
// replace-mode entry by redactedPlaceholder. Redaction is best-effort: it
// covers the encodings in valueForms only.
func (s *Secrets) TransformResponse(ctx context.Context, tctx *transform.TransformContext, req *http.Request, resp *http.Response) (*transform.TransformResult, error) {
	r := newRedactor(s.redactNeedles(ctx, tctx))
	if r == nil {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	redactHeader(r, resp.Header)

	redactTrailers := func() { redactHeader(r, resp.Trailer) }

	if ce := strings.TrimSpace(resp.Header.Get("Content-Encoding")); ce != "" && !strings.EqualFold(ce, "identity") {
		if len(tctx.RedactPairs) > 0 && responseHasBody(req, resp) {
			tctx.Annotate("reject_reason", "content_encoded_response")
			return rejectResult(req, http.StatusBadGateway, msgEncodedResponse), nil
		}
		// Nothing was substituted into this request: forward the encoded body
		// untouched, still redacting trailers once they arrive.
		src := transform.RequireBufferedBody(resp.Body).StreamingReader()
		resp.Body = transform.NewBufferedBody(newRedactReader(src, nil, redactTrailers), 0)
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	src := transform.RequireBufferedBody(resp.Body).StreamingReader()
	resp.Body = transform.NewBufferedBody(newRedactReader(src, r, redactTrailers), 0)
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// responseHasBody reports whether the response can carry a body.
func responseHasBody(req *http.Request, resp *http.Response) bool {
	return req.Method != http.MethodHead &&
		resp.StatusCode != http.StatusNoContent &&
		resp.StatusCode != http.StatusNotModified
}

func redactHeader(r *redactor, h http.Header) {
	for _, vals := range h {
		for i, v := range vals {
			vals[i] = r.replaceString(v)
		}
	}
}

// needle is one encoded form of a real value and its replacement.
type needle struct {
	old []byte
	new []byte
}

// valueForms are the encodings a real value is redacted in.
var valueForms = []func(string) string{
	func(v string) string { return v },
	url.QueryEscape,
	url.PathEscape,
	func(v string) string { return jsonEscape(v, true) },
	func(v string) string { return jsonEscape(v, false) },
	func(v string) string { return strings.ReplaceAll(jsonEscape(v, true), "/", `\/`) },
	func(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) },
	func(v string) string { return base64.URLEncoding.EncodeToString([]byte(v)) },
	func(v string) string { return hex.EncodeToString([]byte(v)) },
}

// jsonEscape returns v as the contents of a JSON string literal.
func jsonEscape(v string, escapeHTML bool) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(escapeHTML)
	_ = enc.Encode(v) // encoding a string cannot fail
	out := strings.TrimSuffix(buf.String(), "\n")
	return out[1 : len(out)-1]
}

// redactNeedles builds the needle set for one response: every form of each
// substituted value (replaced by the same form of its placeholder), then
// every form of the other replace-mode entries' values (replaced by
// redactedPlaceholder). Duplicates keep their first replacement; needles
// shorter than minNeedleLen are dropped. The result is sorted longest first.
func (s *Secrets) redactNeedles(ctx context.Context, tctx *transform.TransformContext) []needle {
	seen := make(map[string]struct{})
	var needles []needle
	add := func(old, new string) {
		if len(old) < minNeedleLen {
			return
		}
		if _, dup := seen[old]; dup {
			return
		}
		seen[old] = struct{}{}
		needles = append(needles, needle{old: []byte(old), new: []byte(new)})
	}

	for _, p := range tctx.RedactPairs {
		for _, form := range valueForms {
			add(form(p.Real), form(p.Placeholder))
		}
	}
	for i := range s.secrets {
		sec := &s.secrets[i]
		if sec.mode != "replace" {
			continue
		}
		v, err := sec.source.Get(ctx)
		if err != nil || v == "" {
			// An unavailable value cannot have been substituted, so there is
			// nothing of it to echo.
			continue
		}
		for _, form := range valueForms {
			add(form(v), redactedPlaceholder)
		}
	}

	sort.SliceStable(needles, func(i, j int) bool { return len(needles[i].old) > len(needles[j].old) })
	return needles
}

// redactor replaces needles leftmost-longest. needles are sorted longest
// first; byFirst indexes them by first byte so most input bytes cost one
// table lookup.
type redactor struct {
	needles []needle
	byFirst [256][]int
	maxLen  int
}

func newRedactor(needles []needle) *redactor {
	if len(needles) == 0 {
		return nil
	}
	r := &redactor{needles: needles}
	for i, n := range needles {
		r.byFirst[n.old[0]] = append(r.byFirst[n.old[0]], i)
		r.maxLen = max(r.maxLen, len(n.old))
	}
	return r
}

func (r *redactor) replaceString(s string) string {
	var out bytes.Buffer
	r.scan([]byte(s), true, &out)
	return out.String()
}

// scan writes the redacted form of buf to out and returns how many bytes of
// buf it consumed. Unless eof is set it stops at the first position where
// the rest of buf is a proper prefix of a needle, so a match split across
// reads is completed by the next call instead of leaking its first half.
func (r *redactor) scan(buf []byte, eof bool, out *bytes.Buffer) int {
	i := 0
	for i < len(buf) {
		cands := r.byFirst[buf[i]]
		if len(cands) == 0 {
			start := i
			for i++; i < len(buf) && len(r.byFirst[buf[i]]) == 0; i++ {
			}
			out.Write(buf[start:i])
			continue
		}
		rest := buf[i:]
		if !eof && len(rest) < r.maxLen {
			for _, k := range cands {
				n := r.needles[k].old
				if len(rest) < len(n) && bytes.HasPrefix(n, rest) {
					return i
				}
			}
		}
		matched := false
		for _, k := range cands {
			n := r.needles[k]
			if bytes.HasPrefix(rest, n.old) {
				out.Write(n.new)
				i += len(n.old)
				matched = true
				break
			}
		}
		if !matched {
			out.WriteByte(buf[i])
			i++
		}
	}
	return i
}

// redactReader streams src through a redactor. It holds back only a buffer
// suffix that could still become a needle, so streamed responses (SSE) are
// not delayed beyond that. onEOF runs once when src reports io.EOF, before
// the last bytes are returned. A nil redactor passes bytes through.
type redactReader struct {
	src   io.Reader
	r     *redactor
	onEOF func()
	buf   []byte
	carry []byte
	out   bytes.Buffer
	err   error
}

func newRedactReader(src io.Reader, r *redactor, onEOF func()) *redactReader {
	return &redactReader{src: src, r: r, onEOF: onEOF, buf: make([]byte, 32*1024)}
}

func (rr *redactReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if rr.out.Len() > 0 {
			return rr.out.Read(p)
		}
		if rr.err != nil {
			return 0, rr.err
		}
		n, err := rr.src.Read(rr.buf)
		rr.carry = append(rr.carry, rr.buf[:n]...)
		switch {
		case err == io.EOF:
			rr.err = err
			rr.onEOF()
			rr.flush(true)
		case err != nil:
			// Drop held bytes: they may be the start of a real value.
			rr.err = err
			rr.carry = nil
		default:
			rr.flush(false)
		}
	}
}

func (rr *redactReader) flush(eof bool) {
	if rr.r == nil {
		rr.out.Write(rr.carry)
		rr.carry = rr.carry[:0]
		return
	}
	n := rr.r.scan(rr.carry, eof, &rr.out)
	rr.carry = append(rr.carry[:0], rr.carry[n:]...)
}

// Close closes src when it is closable.
func (rr *redactReader) Close() error {
	if c, ok := rr.src.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
