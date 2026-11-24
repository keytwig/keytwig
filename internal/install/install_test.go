package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallAllDetectedIdempotentAndUninstall(t *testing.T) {
	home := t.TempDir()
	fakeBin := filepath.Join(home, "keytwig-bin")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers":{"other":{"command":"x"}},"keep":1}`), 0o600)
	os.MkdirAll(filepath.Join(home, ".codex"), 0o700)
	os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("model = \"x\"\n"), 0o600)
	os.MkdirAll(filepath.Join(home, ".hermes"), 0o700)
	os.WriteFile(filepath.Join(home, ".hermes", "config.yaml"), []byte("model: x\nmcp_servers:\n  memtwig:\n    command: m\n"), 0o600)
	os.MkdirAll(filepath.Join(home, ".codeium", "windsurf"), 0o700)

	res, err := Install("all", fakeBin, home, false)
	if err != nil || len(res) != 4 {
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
	claudeSettings, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if !strings.Contains(string(claudeSettings), "PreToolUse") || !strings.Contains(string(claudeSettings), "hook claude") {
		t.Fatalf("claude settings hook missing: %s", claudeSettings)
	}
	windsurf, _ := os.ReadFile(filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"))
	if !strings.Contains(string(windsurf), `"keytwig"`) {
		t.Fatalf("windsurf: %s", windsurf)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude.json.keytwig.bak")); err != nil {
		t.Fatal("no backup")
	}

	// Second install is idempotent.
	res, _ = Install("all", fakeBin, home, false)
	for _, r := range res {
		if r.Changed {
			t.Fatalf("second install changed %s", r.Harness)
		}
	}

	// Check reports all 4 healthy.
	checks := Check(home)
	if len(checks) != 4 {
		t.Fatalf("check len = %d, want 4: %+v", len(checks), checks)
	}
	for _, c := range checks {
		if !c.OK {
			t.Fatalf("expected OK check for %s: %+v", c.Harness, c)
		}
	}

	// Missing binary is flagged by Check.
	if err := os.Remove(fakeBin); err != nil {
		t.Fatal(err)
	}
	checks = Check(home)
	for _, c := range checks {
		if c.OK {
			t.Fatalf("expected non-OK check when binary missing for %s", c.Harness)
		}
	}

	// Dry-run uninstall does not modify files.
	dryRes, err := Uninstall("all", home, true)
	if err != nil || len(dryRes) != 4 {
		t.Fatalf("dry uninstall: %v %+v", err, dryRes)
	}
	if checks := Check(home); len(checks) != 4 {
		t.Fatalf("dry uninstall mutated configs: %+v", checks)
	}

	// Real uninstall removes keytwig while keeping other servers/keys.
	unRes, err := Uninstall("all", home, false)
	if err != nil || len(unRes) != 4 {
		t.Fatalf("uninstall: %v %+v", err, unRes)
	}
	if checks := Check(home); len(checks) != 0 {
		t.Fatalf("expected 0 configured after uninstall, got %+v", checks)
	}
	claudeAfter, _ := os.ReadFile(filepath.Join(home, ".claude.json"))
	if strings.Contains(string(claudeAfter), `"keytwig"`) || !strings.Contains(string(claudeAfter), `"other"`) || !strings.Contains(string(claudeAfter), `"keep"`) {
		t.Fatalf("claude after uninstall: %s", claudeAfter)
	}
	codexAfter, _ := os.ReadFile(filepath.Join(home, ".codex", "config.toml"))
	if strings.Contains(string(codexAfter), "keytwig") || !strings.Contains(string(codexAfter), `model = "x"`) {
		t.Fatalf("codex after uninstall: %s", codexAfter)
	}
	hermesAfter, _ := os.ReadFile(filepath.Join(home, ".hermes", "config.yaml"))
	if strings.Contains(string(hermesAfter), "keytwig") || !strings.Contains(string(hermesAfter), "memtwig") {
		t.Fatalf("hermes after uninstall: %s", hermesAfter)
	}
	claudeSettingsAfter, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if strings.Contains(string(claudeSettingsAfter), "hook claude") {
		t.Fatalf("claude hook not removed: %s", claudeSettingsAfter)
	}
}

func TestInstallNoHooksOption(t *testing.T) {
	home := t.TempDir()
	fakeBin := filepath.Join(home, "keytwig")
	_ = os.WriteFile(fakeBin, []byte("#!/bin/sh\n"), 0o755)
	os.MkdirAll(filepath.Join(home, ".claude"), 0o700)

	if _, err := InstallWithOptions("claude", fakeBin, home, Options{WithHooks: false}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Fatalf("expected no settings.json when WithHooks=false, stat err=%v", err)
	}
}
