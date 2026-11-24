package redact

import (
	"bytes"
	"strings"
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
			w.Write([]byte(input[i:end]))
		}
		w.Close()
		if out.String() != want {
			t.Fatalf("chunk %d: got %q", chunk, out.String())
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
}

func TestEncodedForms(t *testing.T) {
	secret := "p@ss/w0rd+long"
	var out bytes.Buffer
	w := New(&out, map[string]string{"PW": secret})
	w.Write([]byte("b64=cEBzcy93MHJkK2xvbmc= url=p%40ss%2Fw0rd%2Blong raw=p@ss/w0rd+long"))
	w.Close()
	if strings.Contains(out.String(), "cEBzcy93MHJk") || strings.Contains(out.String(), "p%40ss") || strings.Contains(out.String(), secret) {
		t.Fatalf("leak: %q", out.String())
	}
}
