// Package redact replaces secret values in a byte stream, safely across
// write boundaries.
package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Variants are the forms a secret commonly takes in output: as is,
// base64 (std/url, padded or not — e.g. Basic auth headers), URL-encoded,
// JSON-escaped, and hex-encoded (for values of at least 8 bytes).
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
	if len(v) >= 8 {
		add(hex.EncodeToString(b))
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
	mu      sync.Mutex
	out     io.Writer
	byFirst [256][]pattern // longest first per starting byte
	buf     []byte
	count   atomic.Int64
}

// New builds a redacting writer. secrets maps name → value.
func New(out io.Writer, secrets map[string]string) *Writer {
	w := &Writer{out: out}
	var pats []pattern
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
			pats = append(pats, pattern{value: []byte(form), placeholder: ph})
		}
	}
	sort.Slice(pats, func(i, j int) bool { return len(pats[i].value) > len(pats[j].value) })
	for _, p := range pats {
		b := p.value[0]
		w.byFirst[b] = append(w.byFirst[b], p)
	}
	return w
}

// Count returns how many secret replacements have been written so far.
func (w *Writer) Count() int {
	return int(w.count.Load())
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
		cands := w.byFirst[rest[0]]
		for _, p := range cands {
			if bytes.HasPrefix(rest, p.value) {
				out.Write(p.placeholder)
				w.count.Add(1)
				i += len(p.value)
				continue scan
			}
		}
		if !final {
			for _, p := range cands {
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

// AddBasicAuthPairs derives user:pass entries (and therefore their base64
// variants via Variants) for matching *_USER/*_USERNAME and *_PASS/*_PASSWORD
// secret pairs in env, storing them in dst.
func AddBasicAuthPairs(dst, env map[string]string) {
	if len(env) == 0 {
		return
	}
	type pair struct {
		user string
		pass string
	}
	byPrefix := map[string]*pair{}
	getPair := func(prefix string) *pair {
		p := byPrefix[prefix]
		if p == nil {
			p = &pair{}
			byPrefix[prefix] = p
		}
		return p
	}
	for k, val := range env {
		if len(val) < 4 {
			continue
		}
		up := strings.ToUpper(k)
		switch {
		case up == "USER" || up == "USERNAME":
			getPair("").user = val
		case up == "PASS" || up == "PASSWORD":
			getPair("").pass = val
		case strings.HasSuffix(up, "_USERNAME"):
			getPair(strings.TrimSuffix(up, "_USERNAME")).user = val
		case strings.HasSuffix(up, "_USER"):
			getPair(strings.TrimSuffix(up, "_USER")).user = val
		case strings.HasSuffix(up, "_PASSWORD"):
			getPair(strings.TrimSuffix(up, "_PASSWORD")).pass = val
		case strings.HasSuffix(up, "_PASS"):
			getPair(strings.TrimSuffix(up, "_PASS")).pass = val
		}
	}
	for prefix, p := range byPrefix {
		if p.user == "" || p.pass == "" {
			continue
		}
		name := "BASIC_AUTH"
		if prefix != "" {
			name = prefix + "_BASIC_AUTH"
		}
		if _, exists := dst[name]; exists {
			name += "_PAIR"
		}
		dst[name] = p.user + ":" + p.pass
	}
}
