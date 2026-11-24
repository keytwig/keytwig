package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keytwig/keytwig/internal/audit"
	"github.com/keytwig/keytwig/internal/vault"
)

func TestRunMasksAndPolicyAndAudit(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYTWIG_RUNTIME_DIR", filepath.Join(dir, "run"))
	p := vault.Paths{
		Identity: filepath.Join(dir, "id"),
		Vault:    filepath.Join(dir, "v.age"),
		Config:   filepath.Join(dir, "config.toml"),
		Audit:    filepath.Join(dir, "audit.jsonl"),
	}
	vault.Init(p, vault.ModeFile, nil)
	v, _ := vault.Open(p)
	v.Set("API_TOKEN", "tok_supersecret_1", "")
	v.Set("OTHER_TOKEN", "tok_other_secret_2", "")
	v.Save()
	os.WriteFile(p.Config, []byte("[agents.bot]\ndeny = [\"OTHER_*\"]\n"), 0o600)

	s := &Server{Paths: p, Agent: "bot", Cwd: dir}
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"keytwig_run","arguments":{"command":"echo $API_TOKEN tok_supersecret_1","keys":["API_TOKEN"]}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"keytwig_run","arguments":{"command":"echo hi","keys":["OTHER_TOKEN"]}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"keytwig_list","arguments":{}}}`,
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := s.ServeStdio(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "tok_supersecret_1") || strings.Contains(out.String(), "tok_other_secret_2") {
		t.Fatal("secret leaked through MCP")
	}
	var texts []string
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var r struct {
			Result struct {
				Content []struct{ Text string }
				IsError bool
			}
		}
		json.Unmarshal([]byte(line), &r)
		texts = append(texts, r.Result.Content[0].Text)
	}
	if !strings.Contains(texts[0], "‹keytwig:API_TOKEN›") {
		t.Fatalf("run: %s", texts[0])
	}
	if !strings.Contains(texts[1], "not allowed") {
		t.Fatalf("policy: %s", texts[1])
	}
	if strings.Contains(texts[2], "OTHER_TOKEN") || !strings.Contains(texts[2], "API_TOKEN") {
		t.Fatalf("list: %s", texts[2])
	}

	evs, err := audit.Read(p.Audit, "", 10)
	if err != nil || len(evs) != 1 {
		t.Fatalf("audit read: err=%v evs=%+v", err, evs)
	}
	if evs[0].Mode != "mcp" || evs[0].Agent != "bot" || evs[0].Redactions < 1 {
		t.Fatalf("unexpected audit event: %+v", evs[0])
	}
	if strings.Contains(evs[0].Command, "tok_supersecret_1") {
		t.Fatalf("secret leaked in audit command: %q", evs[0].Command)
	}
}

func TestImportRefusesRestrictedFiles(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KEYTWIG_RUNTIME_DIR", filepath.Join(dir, "run"))
	p := vault.Paths{
		Identity: filepath.Join(dir, "id"),
		Vault:    filepath.Join(dir, "v.age"),
		Config:   filepath.Join(dir, "config.toml"),
		Audit:    filepath.Join(dir, "audit.jsonl"),
	}
	vault.Init(p, vault.ModeFile, nil)

	harnessEnv := filepath.Join(home, ".hermes", ".env")
	os.MkdirAll(filepath.Dir(harnessEnv), 0o700)
	os.WriteFile(harnessEnv, []byte("OPENAI_API_KEY=sk-12345678\n"), 0o600)

	backupEnv := filepath.Join(dir, ".env.bak")
	os.WriteFile(backupEnv, []byte("OPENAI_API_KEY=sk-12345678\n"), 0o600)

	projEnv := filepath.Join(dir, "proj", ".env")
	os.MkdirAll(filepath.Dir(projEnv), 0o700)
	os.WriteFile(projEnv, []byte("STRIPE_API_KEY=sk_test_12345678\n"), 0o600)

	s := &Server{Paths: p, Agent: "claude", Cwd: dir}
	for _, tc := range []struct {
		name string
		path string
		want bool // isError
	}{
		{"harness", harnessEnv, true},
		{"backup", backupEnv, true},
		{"project", projEnv, false},
	} {
		req, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name":      "keytwig_import",
				"arguments": map[string]any{"path": tc.path},
			},
		})
		var out bytes.Buffer
		if err := s.ServeStdio(context.Background(), strings.NewReader(string(req)+"\n"), &out); err != nil {
			t.Fatal(err)
		}
		var r struct {
			Result struct {
				Content []struct{ Text string }
				IsError bool
			}
		}
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if r.Result.IsError != tc.want {
			t.Fatalf("%s: isError=%v want=%v text=%q", tc.name, r.Result.IsError, tc.want, r.Result.Content[0].Text)
		}
		if tc.want && !strings.Contains(r.Result.Content[0].Text, "refusing to import harness/backup") {
			t.Fatalf("%s: unexpected msg %q", tc.name, r.Result.Content[0].Text)
		}
	}
}
