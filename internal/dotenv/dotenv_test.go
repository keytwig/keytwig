package dotenv

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	in := `# comment
export A_KEY="quoted value"
B_TOKEN='single'
C_PASS=plain # trailing comment
WP_APP_PASSWORD=abcd efgh ijkl
A_KEY=override
not a line
`
	es, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range es {
		got[e.Name] = e.Value
	}
	want := map[string]string{"A_KEY": "override", "B_TOKEN": "single", "C_PASS": "plain", "WP_APP_PASSWORD": "abcd efgh ijkl"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if len(es) != 4 {
		t.Errorf("entries %d", len(es))
	}
}

func TestLooksSecret(t *testing.T) {
	for n, want := range map[string]bool{
		"STRIPE_SECRET_KEY": true, "STRIPE_PUBLISHABLE_KEY": false, "SMTP_PASS": true,
		"PORT": false, "DB_USER": false, "TELEGRAM_BOT_TOKEN": true,
		"VITE_SENTRY_DSN": false, "BETTER_AUTH_URL": false, "BETTER_AUTH_SECRET": true, "DATABASE_URL": true,
	} {
		if LooksSecret(n) != want {
			t.Errorf("%s: %v", n, !want)
		}
	}
}
