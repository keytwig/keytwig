package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keytwig/keytwig/internal/vault"
)

func TestRunMasksAndPolicy(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYTWIG_RUNTIME_DIR", filepath.Join(dir, "run"))
	p := vault.Paths{Identity: filepath.Join(dir, "id"), Vault: filepath.Join(dir, "v.age"), Config: filepath.Join(dir, "config.toml")}
	vault.Init(p, vault.ModeFile, nil)
	v, _ := vault.Open(p)
	v.Set("API_TOKEN", "tok_supersecret_1", "")
	v.Set("OTHER_TOKEN", "tok_other_secret_2", "")
	v.Save()
	os.WriteFile(p.Config, []byte("[agents.bot]\ndeny = [\"OTHER_*\"]\n"), 0o600)

	s := &Server{Paths: p, Agent: "bot", Cwd: dir}
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"keytwig_run","arguments":{"command":"echo $API_TOKEN","keys":["API_TOKEN"]}}}`,
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
}
