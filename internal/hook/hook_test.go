package hook

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keytwig/keytwig/internal/vault"
)

func testPaths(t *testing.T) (string, vault.Paths) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	p := vault.Paths{
		Identity: filepath.Join(home, ".config", "keytwig", "identity.txt"),
		Vault:    filepath.Join(home, ".local", "share", "keytwig", "vault.age"),
	}
	return home, p
}

func runHook(t *testing.T, in Input, p vault.Paths) Output {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Run(bytes.NewReader(raw), &out, p); err != nil {
		t.Fatal(err)
	}
	var resp Output
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal hook output %q: %v", out.String(), err)
	}
	return resp
}

func TestHookFileReads(t *testing.T) {
	home, p := testPaths(t)
	proj := filepath.Join(home, "app")

	blockedCases := []struct {
		name string
		path string
	}{
		{"dotenv", filepath.Join(proj, ".env")},
		{"dotenv_prod", filepath.Join(proj, ".env.production")},
		{"identity", p.Identity},
		{"vault", p.Vault},
		{"aws", "~/.aws/credentials"},
		{"netrc", "~/.netrc"},
		{"ssh_key", "~/.ssh/id_ed25519"},
	}
	for _, tc := range blockedCases {
		resp := runHook(t, Input{
			ToolName:  "Read",
			ToolInput: map[string]any{"file_path": tc.path},
			Cwd:       proj,
		}, p)
		if resp.HookSpecificOutput == nil || resp.HookSpecificOutput.PermissionDecision != "deny" {
			t.Fatalf("%s: expected deny, got %+v", tc.name, resp)
		}
	}

	allowedCases := []struct {
		name string
		path string
	}{
		{"env_example", filepath.Join(proj, ".env.example")},
		{"env_sample", filepath.Join(proj, ".env.sample")},
		{"ssh_pub", "~/.ssh/id_ed25519.pub"},
		{"source_code", filepath.Join(proj, "main.go")},
	}
	for _, tc := range allowedCases {
		resp := runHook(t, Input{
			ToolName:  "Read",
			ToolInput: map[string]any{"file_path": tc.path},
			Cwd:       proj,
		}, p)
		if resp.HookSpecificOutput != nil {
			t.Fatalf("%s: expected allow, got %+v", tc.name, resp)
		}
	}
}

func TestHookShellCommands(t *testing.T) {
	home, p := testPaths(t)
	proj := filepath.Join(home, "app")

	blocked := []string{
		"cat .env",
		"head -n 20 .env.local",
		"tail -f app.env",
		"grep STRIPE .env",
		"source .env",
		"env",
		"printenv",
		"export -p",
		"cat " + p.Identity,
		"cat ~/.aws/credentials",
		"echo ok && cat .env",
	}
	for _, cmd := range blocked {
		resp := runHook(t, Input{
			ToolName:  "Bash",
			ToolInput: map[string]any{"command": cmd},
			Cwd:       proj,
		}, p)
		if resp.HookSpecificOutput == nil || resp.HookSpecificOutput.PermissionDecision != "deny" {
			t.Fatalf("command %q: expected deny, got %+v", cmd, resp)
		}
		if !strings.Contains(resp.HookSpecificOutput.PermissionDecisionReason, "keytwig_http") {
			t.Fatalf("unexpected reason: %q", resp.HookSpecificOutput.PermissionDecisionReason)
		}
	}

	allowed := []string{
		"keytwig run -p -- npm test",
		"keytwig import .env",
		"keytwig http GET https://api.example.com",
		"cat .env.example",
		"grep -n PORT .env.template",
		"env FOO=bar go test ./...",
		"ls -la",
	}
	for _, cmd := range allowed {
		resp := runHook(t, Input{
			ToolName:  "Bash",
			ToolInput: map[string]any{"command": cmd},
			Cwd:       proj,
		}, p)
		if resp.HookSpecificOutput != nil {
			t.Fatalf("command %q: expected allow, got %+v", cmd, resp)
		}
	}
}
