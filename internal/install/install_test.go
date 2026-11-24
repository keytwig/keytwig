package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallAllDetectedIdempotent(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers":{"other":{"command":"x"}},"keep":1}`), 0o600)
	os.MkdirAll(filepath.Join(home, ".codex"), 0o700)
	os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("model = \"x\"\n"), 0o600)
	os.MkdirAll(filepath.Join(home, ".hermes"), 0o700)
	os.WriteFile(filepath.Join(home, ".hermes", "config.yaml"), []byte("model: x\nmcp_servers:\n  memtwig:\n    command: m\n"), 0o600)

	res, err := Install("all", "/bin/keytwig", home, false)
	if err != nil || len(res) != 3 {
		t.Fatalf("%v %+v", err, res)
	}
	claude, _ := os.ReadFile(filepath.Join(home, ".claude.json"))
	if !strings.Contains(string(claude), `"keytwig"`) || !strings.Contains(string(claude), `"other"`) || !strings.Contains(string(claude), `"keep"`) {
		t.Fatalf("claude: %s", claude)
	}
	codex, _ := os.ReadFile(filepath.Join(home, ".codex", "config.toml"))
	if !strings.Contains(string(codex), `args = ["mcp", "--agent", "codex"]`) {
		t.Fatalf("codex: %s", codex)
	}
	hermes, _ := os.ReadFile(filepath.Join(home, ".hermes", "config.yaml"))
	if !strings.Contains(string(hermes), "  keytwig:\n") || !strings.Contains(string(hermes), "  memtwig:") {
		t.Fatalf("hermes: %s", hermes)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude.json.keytwig.bak")); err != nil {
		t.Fatal("no backup")
	}
	res, _ = Install("all", "/bin/keytwig", home, false)
	for _, r := range res {
		if r.Changed {
			t.Fatalf("second install changed %s", r.Harness)
		}
	}
}
