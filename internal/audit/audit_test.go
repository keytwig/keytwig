package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestAppendAndRead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested")
	p := filepath.Join(dir, "audit.jsonl")

	events := []Event{
		{Time: time.Unix(100, 0).UTC(), Mode: "cli", Agent: "claude", Cwd: "/tmp/a", Command: "curl", Injected: []string{"API_KEY"}, ExitCode: 0, Redactions: 1},
		{Time: time.Unix(200, 0).UTC(), Mode: "mcp", Agent: "hermes", Cwd: "/tmp/b", Command: "node app.js", Injected: []string{"DB_URL"}, ExitCode: 2, Redactions: 0},
		{Time: time.Unix(300, 0).UTC(), Mode: "mcp", Agent: "claude", Cwd: "/tmp/c", Command: "npm test", Denied: []string{"PROD_KEY"}, ExitCode: 0, Redactions: 2},
	}
	for _, ev := range events {
		if err := Append(p, ev); err != nil {
			t.Fatal(err)
		}
	}

	if runtime.GOOS != "windows" {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if perm := st.Mode().Perm(); perm != 0o600 {
			t.Fatalf("audit file perm = %o, want 600", perm)
		}
		dst, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if perm := dst.Mode().Perm(); perm != 0o700 {
			t.Fatalf("audit dir perm = %o, want 700", perm)
		}
	}

	all, err := Read(p, "", 0)
	if err != nil || len(all) != 3 {
		t.Fatalf("read all: %v len=%d", err, len(all))
	}
	last2, err := Read(p, "", 2)
	if err != nil || len(last2) != 2 || last2[0].Command != "node app.js" || last2[1].Command != "npm test" {
		t.Fatalf("read last 2: %v %+v", err, last2)
	}
	claudeOnly, err := Read(p, "claude", 10)
	if err != nil || len(claudeOnly) != 2 || claudeOnly[0].Mode != "cli" || claudeOnly[1].Mode != "mcp" {
		t.Fatalf("read agent filter: %v %+v", err, claudeOnly)
	}
	claude1, err := Read(p, "claude", 1)
	if err != nil || len(claude1) != 1 || claude1[0].Command != "npm test" {
		t.Fatalf("read agent limit 1: %v %+v", err, claude1)
	}
}

func TestReadMissingFile(t *testing.T) {
	got, err := Read(filepath.Join(t.TempDir(), "missing.jsonl"), "", 10)
	if err != nil || len(got) != 0 {
		t.Fatalf("missing file: got=%v err=%v", got, err)
	}
}

func TestRedactCommandAndTruncation(t *testing.T) {
	secrets := map[string]string{"TOKEN": "super_secret_token_123"}
	longCmd := "curl -H 'Authorization: Bearer super_secret_token_123' " + strings.Repeat("a", 200)
	got := RedactCommand(longCmd, secrets)
	if strings.Contains(got, "super_secret_token_123") {
		t.Fatalf("secret leaked in RedactCommand: %q", got)
	}
	if !strings.Contains(got, "‹keytwig:TOKEN›") {
		t.Fatalf("expected placeholder in %q", got)
	}
	if len([]rune(got)) > MaxCommandLen {
		t.Fatalf("expected <= %d runes, got %d", MaxCommandLen, len([]rune(got)))
	}

	p := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := Append(p, Event{Mode: "cli", Command: strings.Repeat("x", 180)}); err != nil {
		t.Fatal(err)
	}
	evs, err := Read(p, "", 10)
	if err != nil || len(evs) != 1 {
		t.Fatal(err, evs)
	}
	if len([]rune(evs[0].Command)) != MaxCommandLen {
		t.Fatalf("stored command len = %d, want %d", len([]rune(evs[0].Command)), MaxCommandLen)
	}
}
