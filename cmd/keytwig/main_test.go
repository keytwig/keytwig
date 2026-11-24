package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func buildCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "keytwig")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-ldflags=-X main.version=0.1.0-test", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build keytwig: %v\n%s", err, out)
	}
	return bin
}

func runCLI(t *testing.T, bin, home, keytwigHome, stdin string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"USERPROFILE=" + home,
		"KEYTWIG_HOME=" + keytwigHome,
	}
	if tmp := os.Getenv("TMPDIR"); tmp != "" {
		env = append(env, "TMPDIR="+tmp)
	}
	cmd.Env = env
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("exec %v: %v", args, err)
		}
	}
	return string(out), code
}

func TestCLIEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh-based CLI run test")
	}
	bin := buildCLI(t)
	home := t.TempDir()
	khome := filepath.Join(t.TempDir(), "keytwig-home")

	// version
	out, code := runCLI(t, bin, home, khome, "", "version")
	if code != 0 || strings.TrimSpace(out) != "keytwig 0.1.0-test" {
		t.Fatalf("version: code=%d out=%q", code, out)
	}

	// init --file
	out, code = runCLI(t, bin, home, khome, "", "init", "--file")
	if code != 0 || !strings.Contains(out, "initialized, identity mode: file") {
		t.Fatalf("init: code=%d out=%q", code, out)
	}

	// set API_KEY via stdin
	out, code = runCLI(t, bin, home, khome, "sk_cli_secret_value_123\n", "set", "API_KEY")
	if code != 0 || !strings.Contains(out, "API_KEY added") {
		t.Fatalf("set: code=%d out=%q", code, out)
	}

	// ls --json (no secret value)
	out, code = runCLI(t, bin, home, khome, "", "ls", "--json")
	if code != 0 || !strings.Contains(out, `"API_KEY"`) || strings.Contains(out, "sk_cli_secret_value_123") {
		t.Fatalf("ls: code=%d out=%q", code, out)
	}

	// run -k API_KEY -- sh -c 'echo $API_KEY'
	out, code = runCLI(t, bin, home, khome, "", "run", "-k", "API_KEY", "--", "sh", "-c", "echo $API_KEY")
	if code != 0 || !strings.Contains(out, "‹keytwig:API_KEY›") || strings.Contains(out, "sk_cli_secret_value_123") {
		t.Fatalf("run: code=%d out=%q", code, out)
	}

	// log --json
	out, code = runCLI(t, bin, home, khome, "", "log", "--json")
	if code != 0 {
		t.Fatalf("log: code=%d out=%q", code, out)
	}
	var events []map[string]any
	if err := json.Unmarshal([]byte(out), &events); err != nil || len(events) != 1 {
		t.Fatalf("log json: err=%v out=%q", err, out)
	}
	if events[0]["mode"] != "cli" || events[0]["redactions"] != float64(1) {
		t.Fatalf("unexpected audit event: %+v", events[0])
	}

	// identity export + identity import --file --force
	expFile := filepath.Join(t.TempDir(), "exported.key")
	out, code = runCLI(t, bin, home, khome, "", "identity", "export", "--out", expFile)
	if code != 0 {
		t.Fatalf("identity export: code=%d out=%q", code, out)
	}
	out, code = runCLI(t, bin, home, khome, "", "identity", "import", expFile, "--file")
	if code == 0 {
		t.Fatalf("expected identity import without --force to fail: %q", out)
	}
	out, code = runCLI(t, bin, home, khome, "", "identity", "import", expFile, "--file", "--force")
	if code != 0 || !strings.Contains(out, "imported identity, mode: file") {
		t.Fatalf("identity import --force: code=%d out=%q", code, out)
	}

	// import .env -> rewrite --apply -> restore --apply
	projDir := filepath.Join(home, "myproj")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(projDir, ".env")
	if err := os.WriteFile(envPath, []byte("STRIPE_KEY=sk_live_cli_test_999\nPORT=3000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code = runCLI(t, bin, home, khome, "", "import", envPath)
	if code != 0 || !strings.Contains(out, "STRIPE_KEY") {
		t.Fatalf("import: code=%d out=%q", code, out)
	}
	out, code = runCLI(t, bin, home, khome, "", "rewrite", envPath, "--apply")
	if code != 0 || !strings.Contains(out, "keytwig://STRIPE_KEY") {
		t.Fatalf("rewrite: code=%d out=%q", code, out)
	}
	rewritten, _ := os.ReadFile(envPath)
	if strings.Contains(string(rewritten), "sk_live_cli_test_999") || !strings.Contains(string(rewritten), "keytwig://STRIPE_KEY") {
		t.Fatalf("rewritten env unexpected: %s", rewritten)
	}
	out, code = runCLI(t, bin, home, khome, "", "restore", envPath, "--apply")
	if code != 0 {
		t.Fatalf("restore: code=%d out=%q", code, out)
	}
	restored, _ := os.ReadFile(envPath)
	if !strings.Contains(string(restored), "STRIPE_KEY=sk_live_cli_test_999") {
		t.Fatalf("restored env unexpected: %s", restored)
	}

	// doctor
	out, code = runCLI(t, bin, home, khome, "", "doctor")
	if code != 0 || !strings.Contains(out, "[OK]   identity: file") || !strings.Contains(out, "[OK]   config: valid") {
		t.Fatalf("doctor: code=%d out=%q", code, out)
	}

	// set --file, ls [file], run --file-key
	saPath := filepath.Join(t.TempDir(), "sa.json")
	if err := os.WriteFile(saPath, []byte(`{"private_key":"pem-cli-secret-888"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code = runCLI(t, bin, home, khome, "", "set", "GCP_SA", "--file", saPath)
	if code != 0 || !strings.Contains(out, "GCP_SA added [file]") {
		t.Fatalf("set --file: code=%d out=%q", code, out)
	}
	out, code = runCLI(t, bin, home, khome, "", "ls")
	if code != 0 || !strings.Contains(out, "GCP_SA [file]") {
		t.Fatalf("ls [file]: code=%d out=%q", code, out)
	}
	out, code = runCLI(t, bin, home, khome, "", "run", "--file-key", "SA_FILE=GCP_SA", "--", "sh", "-c", "cat \"$SA_FILE\"")
	if code != 0 || !strings.Contains(out, "‹keytwig:GCP_SA›") || strings.Contains(out, "pem-cli-secret-888") {
		t.Fatalf("run --file-key: code=%d out=%q", code, out)
	}

	// hook claude: deny .env, allow .env.example
	out, code = runCLI(t, bin, home, khome, `{"tool_name":"Read","tool_input":{"file_path":".env"}}`, "hook", "claude")
	if code != 0 || !strings.Contains(out, `"permissionDecision":"deny"`) {
		t.Fatalf("hook deny: code=%d out=%q", code, out)
	}
	out, code = runCLI(t, bin, home, khome, `{"tool_name":"Read","tool_input":{"file_path":".env.example"}}`, "hook", "claude")
	if code != 0 || strings.TrimSpace(out) != "{}" {
		t.Fatalf("hook allow: code=%d out=%q", code, out)
	}

	// http command + config.toml allowed_hosts + doctor expiry checks
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("auth=" + r.Header.Get("Authorization")))
	}))
	defer srv.Close()

	soon := time.Now().Add(5 * 24 * time.Hour).Format("2006-01-02")
	past := time.Now().Add(-5 * 24 * time.Hour).Format("2006-01-02")
	cfgRaw := "[secrets.API_KEY]\nallowed_hosts = [\"127.0.0.1\"]\nexpires = \"" + soon + "\"\n\n[secrets.OLD_KEY]\nexpires = \"" + past + "\"\n"
	if err := os.WriteFile(filepath.Join(khome, "config.toml"), []byte(cfgRaw), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code = runCLI(t, bin, home, khome, "", "http", "GET", srv.URL+"/ok", "-H", "Authorization: Bearer {{API_KEY}}")
	if code != 0 || !strings.Contains(out, "‹keytwig:API_KEY›") || strings.Contains(out, "sk_cli_secret_value_123") {
		t.Fatalf("http: code=%d out=%q", code, out)
	}

	out, code = runCLI(t, bin, home, khome, "", "doctor")
	if code == 0 || !strings.Contains(out, "[WARN] secret API_KEY: expires in") || !strings.Contains(out, "[FAIL] secret OLD_KEY: expired on") {
		t.Fatalf("doctor expiry: code=%d out=%q", code, out)
	}
}
