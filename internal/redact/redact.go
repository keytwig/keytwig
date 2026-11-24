// Package redact replaces secret values in a byte stream, safely across
// write boundaries.
package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// Variants are the forms a secret commonly takes in output: as is,
// base64 (std/url, padded or not — e.g. Basic auth headers), URL-encoded,
// JSON-escaped.
func Variants(v string) []string {
	out := []string{v}
	add := func(s string) {
		for _, o := range out {
			if o == s {
				return
			}
		}
		out = append(out, s)
	}
	b := []byte(v)
	add(base64.StdEncoding.EncodeToString(b))
	add(base64.RawStdEncoding.EncodeToString(b))
	add(base64.URLEncoding.EncodeToString(b))
	add(base64.RawURLEncoding.EncodeToString(b))
	add(url.QueryEscape(v))
	add(url.PathEscape(v))
	if j, err := json.Marshal(v); err == nil {
		add(strings.Trim(string(j), `"`))
	}
	return out
}

// MinLen is the shortest value that gets redacted; shorter ones would
// mangle ordinary output (e.g. "true", "1234").
const MinLen = 6

type pattern struct {
	value       []byte
	placeholder []byte
}

type Writer struct {
	mu   sync.Mutex
	out  io.Writer
	pats []pattern // longest first
	buf  []byte
}

// New builds a redacting writer. secrets maps name → value.
func New(out io.Writer, secrets map[string]string) *Writer {
	w := &Writer{out: out}
	seen := map[string]bool{}
	for name, v := range secrets {
		if len(v) < MinLen {
			continue
		}
		ph := []byte("‹keytwig:" + name + "›")
		for _, form := range Variants(v) {
			if len(form) < MinLen || seen[form] {
				continue
			}
			seen[form] = true
			w.pats = append(w.pats, pattern{value: []byte(form), placeholder: ph})
		}
	}
	sort.Slice(w.pats, func(i, j int) bool { return len(w.pats[i].value) > len(w.pats[j].value) })
	return w
}

func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	if err := w.drain(false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close flushes whatever is held back.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.drain(true)
}

func (w *Writer) drain(final bool) error {
	var out bytes.Buffer
	i := 0
scan:
	for i < len(w.buf) {
		rest := w.buf[i:]
		for _, p := range w.pats {
			if bytes.HasPrefix(rest, p.value) {
				out.Write(p.placeholder)
				i += len(p.value)
				continue scan
			}
		}
		if !final {
			for _, p := range w.pats {
				if len(rest) < len(p.value) && bytes.HasPrefix(p.value, rest) {
					break scan // could become a secret with the next write
				}
			}
		}
		out.WriteByte(w.buf[i])
		i++
	}
	w.buf = append(w.buf[:0], w.buf[i:]...)
	if out.Len() == 0 {
		return nil
	}
	_, err := w.out.Write(out.Bytes())
	return err
}
