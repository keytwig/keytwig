package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyAndDedup(t *testing.T) {
	home := t.TempDir()
	w := func(rel, body string) {
		p := filepath.Join(home, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, []byte(body), 0o600)
	}
	w(".hermes/.env", "STRIPE_SECRET_KEY=sk_shared\n")
	w(".hermes/.env.bak-1", "STRIPE_SECRET_KEY=sk_shared\n")
	w("code/shop/.env", "STRIPE_SECRET_KEY=sk_shared\nSTRIPE_SECRET_KEY_PROD=sk_shared\nSMTP_PASS=p1\n")
	w("code/blog/.env", "SMTP_PASS=p2\n")
	w("code/blog/.env.bak-old", "SMTP_PASS=p2\n")
	w(".keys/x.env", "X_TOKEN=t\n")

	o := Options{Harness: []string{filepath.Join(home, ".hermes")}, Home: home}
	rep, err := Run([]string{home}, nil, o)
	if err != nil {
		t.Fatal(err)
	}
	class := map[string]string{}
	for _, f := range rep.EnvFiles {
		rel, _ := filepath.Rel(home, f.Path)
		class[filepath.ToSlash(rel)] = f.Class
	}
	want := map[string]string{
		".hermes/.env": ClassHarness, ".hermes/.env.bak-1": ClassHarness,
		"code/shop/.env": ClassProject, "code/blog/.env": ClassProject,
		"code/blog/.env.bak-old": ClassBackup, ".keys/x.env": ClassApp,
	}
	for k, v := range want {
		if class[k] != v {
			t.Errorf("%s: %s, want %s", k, class[k], v)
		}
	}
	// values: sk_shared, p1, p2, t
	if rep.UniqueValues != 4 {
		t.Errorf("unique %d", rep.UniqueValues)
	}
	// project-only values not in vault: sk_shared, p1, p2
	if rep.ToImport != 3 {
		t.Errorf("to import %d", rep.ToImport)
	}
	if len(rep.SameValue) != 1 || len(rep.SameValue[0].Names) != 2 {
		t.Errorf("same value groups %+v", rep.SameValue)
	}
}
