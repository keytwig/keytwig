package runner

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keytwig/keytwig/internal/config"
	"github.com/keytwig/keytwig/internal/vault"
)

func setupVault(t *testing.T) (*vault.Vault, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KEYTWIG_RUNTIME_DIR", filepath.Join(dir, "run"))
	p := vault.Paths{
		Identity: filepath.Join(dir, "id.txt"),
		Vault:    filepath.Join(dir, "v.age"),
		Config:   filepath.Join(dir, "config.toml"),
	}
	if _, err := vault.Init(p, vault.ModeFile, nil); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	v.Set("OPENAI_KEY", "sk-openai-secret-123", "test")
	v.Set("OPENAI_ALIAS", "sk-openai-secret-123", "test")
	v.Set("PROD_SECRET", "prod-secret-value-99", "test")
	v.Set("OTHER_KEY", "other-secret-value-7", "test")
	projDir := filepath.Join(dir, "proj")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}
	v.Link(projDir, "API_TOKEN", "OPENAI_KEY")
	v.Link(projDir, "PROD_TOKEN", "PROD_SECRET")
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	return v, projDir
}

func TestResolveSpecAndPolicy(t *testing.T) {
	v, projDir := setupVault(t)
	cfg := config.Config{
		Agents: map[string]config.AgentPolicy{
			"bot": {
				Allow: []string{"OPENAI_*", "OTHER_*"},
				Deny:  []string{"*_ALIAS", "PROD_*"},
			},
		},
	}

	// Keys + VAR=NAME mapping
	res, err := Resolve(v, cfg, Spec{Keys: []string{"OTHER_KEY", "MY_KEY=OPENAI_KEY"}, Agent: "unlisted"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Env["OTHER_KEY"] != "other-secret-value-7" || res.Env["MY_KEY"] != "sk-openai-secret-123" {
		t.Fatalf("unexpected env: %+v", res.Env)
	}

	// Alias cannot dodge deny
	if _, err := Resolve(v, cfg, Spec{Keys: []string{"OPENAI_KEY"}, Agent: "bot"}); err == nil {
		t.Fatal("expected alias deny to reject OPENAI_KEY for bot")
	}

	// Project scope collects allowed and records denied
	subDir := filepath.Join(projDir, "sub")
	_ = os.MkdirAll(subDir, 0o700)
	resProj, err := Resolve(v, cfg, Spec{Project: true, Cwd: subDir, Agent: "bot"})
	if err != nil {
		t.Fatal(err)
	}
	if resProj.ProjectDir != projDir || len(resProj.Injected) != 0 || len(resProj.Denied) != 2 {
		t.Fatalf("unexpected project resolution: %+v", resProj)
	}

	resProjFull, err := Resolve(v, config.Config{}, Spec{Project: true, Cwd: subDir})
	if err != nil {
		t.Fatal(err)
	}
	if resProjFull.Env["API_TOKEN"] != "sk-openai-secret-123" || resProjFull.Env["PROD_TOKEN"] != "prod-secret-value-99" {
		t.Fatalf("project env: %+v", resProjFull.Env)
	}

	// EnvFile with keytwig:// ref + plain entry
	envPath := filepath.Join(projDir, ".env")
	_ = os.WriteFile(envPath, []byte("PLAIN=hello\nREF=keytwig://OTHER_KEY\n"), 0o600)
	resEnv, err := Resolve(v, cfg, Spec{EnvFile: envPath, Agent: "bot"})
	if err != nil {
		t.Fatal(err)
	}
	if resEnv.Env["PLAIN"] != "hello" || resEnv.Env["REF"] != "other-secret-value-7" {
		t.Fatalf("envfile resolution: %+v", resEnv.Env)
	}
}

func TestRunMasksStdoutStderrExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh test")
	}
	v, _ := setupVault(t)
	res, err := Resolve(v, config.Config{}, Spec{Keys: []string{"OPENAI_KEY", "OTHER_KEY"}})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	rr, err := Run(context.Background(), v, res, Exec{
		Shell:  "printf 'out=%s\n' \"$OPENAI_KEY\"; printf 'err=%s\n' \"$OTHER_KEY\" >&2; exit 7",
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rr.ExitCode != 7 {
		t.Fatalf("exit code = %d, want 7", rr.ExitCode)
	}
	if rr.Redactions != 2 {
		t.Fatalf("redactions = %d, want 2", rr.Redactions)
	}
	if strings.Contains(stdout.String(), "sk-openai-secret-123") || !strings.Contains(stdout.String(), "‹keytwig:OPENAI_KEY›") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if strings.Contains(stderr.String(), "other-secret-value-7") || !strings.Contains(stderr.String(), "‹keytwig:OTHER_KEY›") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunTimeoutKillsProcessGroup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix process group test")
	}
	v, _ := setupVault(t)
	res := &Resolution{Env: map[string]string{}}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	var out bytes.Buffer
	rr, err := Run(ctx, v, res, Exec{
		Shell:  "sleep 30 & wait",
		Stdout: &out,
		Stderr: &out,
	})
	elapsed := time.Since(start)
	if err != nil && ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("unexpected err: %v", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("timeout took too long (%s), child process group leaked", elapsed)
	}
	if rr.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code on timeout, got %+v", rr)
	}
}

func TestRunFileKeysMountAndCleanup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh test")
	}
	v, _ := setupVault(t)
	saJSON := `{"type":"service_account","private_key":"secret-key-xyz"}`
	v.SetFile("GCP_SA", saJSON, "service-account.json", "test")
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{
		Agents: map[string]config.AgentPolicy{
			"restricted": {Deny: []string{"GCP_*"}},
		},
	}
	if _, err := Resolve(v, cfg, Spec{FileKeys: []string{"GOOGLE_APPLICATION_CREDENTIALS=GCP_SA"}, Agent: "restricted"}); err == nil {
		t.Fatal("expected policy deny for file key")
	}

	res, err := Resolve(v, cfg, Spec{FileKeys: []string{"GOOGLE_APPLICATION_CREDENTIALS=GCP_SA"}, Agent: "allowed"})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	rr, err := Run(context.Background(), v, res, Exec{
		Shell:  `printf 'path=%s\n' "$GOOGLE_APPLICATION_CREDENTIALS"; cat "$GOOGLE_APPLICATION_CREDENTIALS"`,
		Stdout: &out,
		Stderr: &out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rr.ExitCode != 0 {
		t.Fatalf("exit code = %d out=%s", rr.ExitCode, out.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) < 1 || !strings.HasPrefix(lines[0], "path=") {
		t.Fatalf("unexpected output: %q", out.String())
	}
	mountedPath := strings.TrimPrefix(lines[0], "path=")
	if filepath.Base(mountedPath) != "service-account.json" {
		t.Fatalf("expected basename service-account.json, got %q", mountedPath)
	}
	if strings.Contains(out.String(), "secret-key-xyz") || !strings.Contains(out.String(), "‹keytwig:GCP_SA›") {
		t.Fatalf("file secret content leaked: %q", out.String())
	}
	if _, err := os.Stat(mountedPath); !os.IsNotExist(err) {
		t.Fatalf("expected mounted file %s to be wiped and removed, stat err=%v", mountedPath, err)
	}
}

func TestRunRedactsBasicAuthPair(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh test")
	}
	v, _ := setupVault(t)
	v.Set("API_USER", "alice_user", "test")
	v.Set("API_PASS", "s3cr3t_pass", "test")
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	res, err := Resolve(v, config.Config{}, Spec{Keys: []string{"API_USER", "API_PASS"}})
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString([]byte("alice_user:s3cr3t_pass"))
	var out bytes.Buffer
	rr, err := Run(context.Background(), v, res, Exec{
		Shell:  "printf 'Basic %s\n' '" + b64 + "'",
		Stdout: &out,
		Stderr: &out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), b64) {
		t.Fatalf("Basic auth base64 leaked: %q", out.String())
	}
	if !strings.Contains(out.String(), "‹keytwig:API_BASIC_AUTH›") || rr.Redactions < 1 {
		t.Fatalf("expected Basic auth redaction, got %q redactions=%d", out.String(), rr.Redactions)
	}
}
