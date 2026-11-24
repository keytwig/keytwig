package redact

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestRedactAcrossWrites(t *testing.T) {
	secrets := map[string]string{"API": "sk_live_abcdef123", "SHORT": "abc", "PW": "hunter22"}
	input := "token=sk_live_abcdef123 pw=hunter22 short=abc end"
	want := "token=‹keytwig:API› pw=‹keytwig:PW› short=abc end"
	for chunk := 1; chunk <= len(input); chunk++ {
		var out bytes.Buffer
		w := New(&out, secrets)
		for i := 0; i < len(input); i += chunk {
			end := i + chunk
			if end > len(input) {
				end = len(input)
			}
			if _, err := w.Write([]byte(input[i:end])); err != nil {
				t.Fatalf("chunk %d write: %v", chunk, err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatalf("chunk %d close: %v", chunk, err)
		}
		if out.String() != want {
			t.Fatalf("chunk %d: got %q", chunk, out.String())
		}
		if w.Count() != 2 {
			t.Fatalf("chunk %d: count got %d, want 2", chunk, w.Count())
		}
	}
}

func TestLongestFirstAndPartialPrefixFlushed(t *testing.T) {
	secrets := map[string]string{"A": "secret12", "B": "secret1234"}
	var out bytes.Buffer
	w := New(&out, secrets)
	w.Write([]byte("x secret1234 y secret1"))
	w.Close()
	got := out.String()
	if got != "x ‹keytwig:B› y secret1" {
		t.Fatalf("got %q", got)
	}
	if strings.Contains(got, "secret12 ") {
		t.Fatal("leak")
	}
	if w.Count() != 1 {
		t.Fatalf("count = %d, want 1", w.Count())
	}
}

func TestEncodedFormsAndHexThreshold(t *testing.T) {
	secret := "p@ss/w0rd+long"
	shortHex := "abcdefg" // len 7 (< 8): hex should NOT be added
	var out bytes.Buffer
	w := New(&out, map[string]string{"PW": secret, "SHORT7": shortHex})
	hexSecret := hex.EncodeToString([]byte(secret))
	hexShort7 := hex.EncodeToString([]byte(shortHex))
	w.Write([]byte("b64=cEBzcy93MHJkK2xvbmc= url=p%40ss%2Fw0rd%2Blong hex=" + hexSecret + " shorthex=" + hexShort7 + " raw=" + secret))
	w.Close()
	got := out.String()
	if strings.Contains(got, "cEBzcy93MHJk") || strings.Contains(got, "p%40ss") || strings.Contains(got, hexSecret) || strings.Contains(got, secret) {
		t.Fatalf("leak: %q", got)
	}
	if !strings.Contains(got, "shorthex="+hexShort7) {
		t.Fatalf("7-char secret hex should not be redacted: %q", got)
	}
	if w.Count() != 4 {
		t.Fatalf("count = %d, want 4", w.Count())
	}
}

func TestWriterCountConcurrent(t *testing.T) {
	var out bytes.Buffer
	w := New(&out, map[string]string{"TOK": "token_value_123"})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_, _ = fmt.Fprintf(w, "line-%d-%d=token_value_123\n", id, j)
				_ = w.Count()
			}
		}(i)
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if w.Count() != 160 {
		t.Fatalf("count = %d, want 160", w.Count())
	}
	if strings.Contains(out.String(), "token_value_123") {
		t.Fatal("leak")
	}
}

func BenchmarkWriter(b *testing.B) {
	secrets := map[string]string{
		"API_KEY":   "sk_live_51NxYz1234567890",
		"DB_PASS":   "super_secret_db_password_99",
		"JWT_TOKEN": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
	}
	chunk := bytes.Repeat([]byte("normal log output without secrets; "), 100)
	chunk = append(chunk, []byte("token=sk_live_51NxYz1234567890 done\n")...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := New(bytes.NewBuffer(nil), secrets)
		_, _ = w.Write(chunk)
		_ = w.Close()
	}
}
