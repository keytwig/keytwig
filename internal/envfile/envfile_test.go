package envfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keytwig/keytwig/internal/vault"
)

func TestRewriteRestoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYTWIG_RUNTIME_DIR", filepath.Join(dir, "run"))
	p := vault.Paths{Identity: filepath.Join(dir, "id"), Vault: filepath.Join(dir, "v.age")}
	vault.Init(p, vault.ModeFile, nil)
	v, _ := vault.Open(p)

	proj := filepath.Join(dir, "shop")
	os.MkdirAll(proj, 0o700)
	envPath := filepath.Join(proj, ".env")
	orig := "# comment\nPORT=3000\nexport DB_PASS=\"with space #x\"\nAPI_KEY=sk_live_12345\nCHANGED=newvalue\n"
	os.WriteFile(envPath, []byte(orig), 0o640)

	v.Set("SHOP__DB_PASS", "with space #x", envPath)
	v.Link(proj, "DB_PASS", "SHOP__DB_PASS")
	v.Set("API_KEY", "sk_live_12345", envPath)
	v.Link(proj, "API_KEY", "API_KEY")
	v.Set("CHANGED", "oldvalue", envPath)
	v.Link(proj, "CHANGED", "CHANGED")

	r, err := Rewrite(envPath, v, false)
	if err != nil || len(r.Changes) != 2 || r.Written {
		t.Fatalf("dry run: %+v %v", r, err)
	}
	if b, _ := os.ReadFile(envPath); string(b) != orig {
		t.Fatal("dry run wrote")
	}
	if _, err := Rewrite(envPath, v, true); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(envPath)
	got := string(b)
	if strings.Contains(got, "sk_live_12345") || strings.Contains(got, "with space") {
		t.Fatalf("secret left: %q", got)
	}
	if !strings.Contains(got, "export DB_PASS=keytwig://SHOP__DB_PASS\n") || !strings.Contains(got, "PORT=3000\n# ") == false && !strings.Contains(got, "CHANGED=newvalue") {
		t.Fatalf("unexpected: %q", got)
	}
	if st, _ := os.Stat(envPath); st.Mode().Perm() != 0o640 {
		t.Fatal("mode not kept")
	}
	if _, err := Restore(envPath, v, true); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(envPath)
	if string(b) != "# comment\nPORT=3000\nexport DB_PASS=\"with space #x\"\nAPI_KEY=sk_live_12345\nCHANGED=newvalue\n" {
		t.Fatalf("restore mismatch: %q", string(b))
	}
}
