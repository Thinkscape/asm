package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/ironsh/iron-proxy/internal/transform"
)

// bodyKind classifies a request body by its Content-Type.
type bodyKind int

const (
	bodyOther bodyKind = iota
	bodyForm
	bodyJSON
	bodyMultipart
)

// requestBodyKind classifies the request body from its Content-Type header.
func requestBodyKind(req *http.Request) bodyKind {
	mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil {
		return bodyOther
	}
	switch {
	case mediaType == "application/x-www-form-urlencoded":
		return bodyForm
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		return bodyJSON
	case mediaType == "multipart/form-data":
		return bodyMultipart
	default:
		return bodyOther
	}
}

// identityEncoded reports whether the request carries no Content-Encoding
// other than identity.
func identityEncoded(h http.Header) bool {
	for _, v := range h.Values("Content-Encoding") {
		for _, coding := range strings.Split(v, ",") {
			coding = strings.TrimSpace(coding)
			if coding != "" && !strings.EqualFold(coding, "identity") {
				return false
			}
		}
	}
	return true
}

// scannableBody returns the request body for sentinel scanning. ok is false
// when the body cannot be scanned: it is not a *transform.BufferedBody, it is
// content-encoded, its declared length exceeds the buffering limit, its length
// is unknown and it is neither form nor JSON, or it was truncated while
// buffering. A nil body gives nil, false, nil.
//
// Scanning for out-of-scope sentinels is best effort: over-limit,
// unknown-length non-form/JSON and content-encoded bodies are not scanned.
// Login entries fail closed on such bodies instead.
func scannableBody(req *http.Request) (data []byte, ok bool, err error) {
	if req.Body == nil {
		return nil, false, nil
	}
	bb, buffered := req.Body.(*transform.BufferedBody)
	if !buffered || !identityEncoded(req.Header) {
		return nil, false, nil
	}
	maxBytes := bb.MaxBytes()
	kind := requestBodyKind(req)
	sized := req.ContentLength >= 0 && (maxBytes == 0 || req.ContentLength <= maxBytes)
	streamed := req.ContentLength < 0 && (kind == bodyForm || kind == bodyJSON)
	if !sized && !streamed {
		return nil, false, nil
	}
	bb.Reset()
	data, err = io.ReadAll(bb)
	bb.Reset()
	if err != nil {
		return nil, false, err
	}
	if bb.Truncated() {
		return nil, false, nil
	}
	return data, true, nil
}

// escapeReal encodes a real value for substitution into a body of the given
// kind: query-escaped for forms, JSON-string-escaped (without the surrounding
// quotes) for JSON, unchanged otherwise.
func escapeReal(kind bodyKind, real string) string {
	switch kind {
	case bodyForm:
		return url.QueryEscape(real)
	case bodyJSON:
		quoted := jsonString(real)
		return quoted[1 : len(quoted)-1]
	default:
		return real
	}
}

// jsonString returns the JSON encoding of s, quotes included, without HTML
// escaping.
func jsonString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	// Encoding a Go string cannot fail.
	_ = enc.Encode(s)
	return strings.TrimSuffix(buf.String(), "\n")
}

// swapLoginForm replaces the one form value that is exactly the sentinel
// with the query-escaped real value. Every other byte of the body is kept.
// ok is false unless the raw body contains the sentinel exactly once, as the
// entire decoded value of exactly one field whose name does not contain it.
func swapLoginForm(data []byte, sentinel, real string) ([]byte, bool) {
	if bytes.Count(data, []byte(sentinel)) != 1 {
		return nil, false
	}
	segments := strings.Split(string(data), "&")
	match := -1
	for i, seg := range segments {
		rawName, rawValue, _ := strings.Cut(seg, "=")
		name, nameErr := url.QueryUnescape(rawName)
		value, valueErr := url.QueryUnescape(rawValue)
		if nameErr != nil || valueErr != nil {
			// An undecodable segment holding the sentinel cannot be the
			// sentinel's field; the count check above has seen its bytes.
			if strings.Contains(seg, sentinel) {
				return nil, false
			}
			continue
		}
		if strings.Contains(name, sentinel) {
			return nil, false
		}
		if !strings.Contains(value, sentinel) {
			continue
		}
		if value != sentinel || match >= 0 || !strings.Contains(rawValue, sentinel) {
			return nil, false
		}
		match = i
	}
	if match < 0 {
		return nil, false
	}
	rawName, _, _ := strings.Cut(segments[match], "=")
	segments[match] = rawName + "=" + url.QueryEscape(real)
	return []byte(strings.Join(segments, "&")), true
}

// swapLoginJSON replaces the one JSON string value that is exactly the
// sentinel with the JSON encoding of the real value. ok is false unless the
// body is a single well-formed JSON value whose raw bytes contain the
// sentinel exactly once, as an entire unescaped string value (not a key).
func swapLoginJSON(data []byte, sentinel, real string) ([]byte, bool) {
	if bytes.Count(data, []byte(sentinel)) != 1 {
		return nil, false
	}
	type frame struct {
		object  bool
		wantKey bool // object only: the next token is a key
	}
	want := `"` + sentinel + `"`
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var stack []frame
	start, end := -1, -1
	topLevel := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, false
		}
		if delim, isDelim := tok.(json.Delim); isDelim && (delim == '}' || delim == ']') {
			stack = stack[:len(stack)-1]
			continue
		}

		if len(stack) == 0 {
			topLevel++
			if topLevel > 1 {
				return nil, false
			}
		} else if top := &stack[len(stack)-1]; top.object {
			if top.wantKey {
				// Keys are always strings.
				if key, _ := tok.(string); strings.Contains(key, sentinel) {
					return nil, false
				}
				top.wantKey = false
				continue
			}
			top.wantKey = true
		}

		switch t := tok.(type) {
		case json.Delim:
			stack = append(stack, frame{object: t == '{', wantKey: t == '{'})
		case string:
			if !strings.Contains(t, sentinel) {
				continue
			}
			off := int(dec.InputOffset())
			if t != sentinel || start >= 0 || off < len(want) || string(data[off-len(want):off]) != want {
				return nil, false
			}
			start, end = off-len(want), off
		}
	}
	if start < 0 || len(stack) != 0 {
		return nil, false
	}
	out := make([]byte, 0, len(data)-len(want)+len(real)+2)
	out = append(out, data[:start]...)
	out = append(out, jsonString(real)...)
	out = append(out, data[end:]...)
	return out, true
}
