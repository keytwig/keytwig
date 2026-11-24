package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAllowed(t *testing.T) {
	c := Config{Agents: map[string]AgentPolicy{
		"hermes":  {Allow: []string{"ACME_*"}, Deny: []string{"*_PROD"}},
		"default": {Deny: []string{"STRIPE_*"}},
	}}
	cases := []struct {
		agent string
		names []string
		want  bool
	}{
		{"hermes", []string{"ACME_DB"}, true},
		{"hermes", []string{"OTHER"}, false},
		{"hermes", []string{"ACME_KEY_PROD"}, false},
		{"hermes", []string{"OTHER", "ACME_ALIAS"}, true},
		{"", []string{"STRIPE_KEY"}, false},
		{"unknown", []string{"ANY"}, true},
		{"unknown", []string{"ANY", "STRIPE_ALIAS"}, false}, // alias cannot dodge deny
	}
	for _, c2 := range cases {
		if got := c.Allowed(c2.agent, c2.names...); got != c2.want {
			t.Errorf("%s %v = %v", c2.agent, c2.names, got)
		}
	}
	if !(Config{}).Allowed("x", "Y") {
		t.Error("no policy should allow all")
	}
}

func TestSecretPolicyHostsAndLoad(t *testing.T) {
	cfg := Config{
		Secrets: map[string]SecretPolicy{
			"STRIPE_KEY": {
				AllowedHosts: []string{"API.Stripe.COM:443", "api.stripe.com"},
				Expires:      "2026-12-31",
				Note:         "Stripe live key",
			},
			"OPENAI_ALIAS": {
				AllowedHosts: []string{"*.openai.com"},
			},
		},
	}

	hosts := cfg.AllowedHosts("STRIPE_KEY", "STRIPE_ALIAS")
	if !reflect.DeepEqual(hosts, []string{"api.stripe.com"}) {
		t.Fatalf("AllowedHosts = %v", hosts)
	}
	if !cfg.HostAllowed("api.stripe.com", "STRIPE_KEY") || !cfg.HostAllowed("API.STRIPE.COM:8443", "STRIPE_KEY") {
		t.Fatal("expected exact host match")
	}
	if cfg.HostAllowed("evil.stripe.com", "STRIPE_KEY") {
		t.Fatal("unexpected subdomain match for exact host")
	}
	if cfg.HostAllowed("api.stripe.com", "UNCONFIGURED") {
		t.Fatal("empty allowed_hosts must deny by default")
	}

	// Wildcard subdomain matching via alias
	if !cfg.HostAllowed("api.openai.com", "OPENAI_KEY", "OPENAI_ALIAS") {
		t.Fatal("expected wildcard subdomain match via alias")
	}
	if !cfg.HostAllowed("v1.api.openai.com", "OPENAI_KEY", "OPENAI_ALIAS") {
		t.Fatal("expected nested subdomain match")
	}
	if cfg.HostAllowed("openai.com", "OPENAI_KEY", "OPENAI_ALIAS") {
		t.Fatal("wildcard must not match apex domain")
	}
	if cfg.HostAllowed("evil-openai.com", "OPENAI_KEY", "OPENAI_ALIAS") {
		t.Fatal("wildcard must not match suffix spoofing domain")
	}

	// TOML round-trip
	tomlPath := filepath.Join(t.TempDir(), "config.toml")
	raw := `
[secrets.STRIPE_SECRET_KEY]
allowed_hosts = ["api.stripe.com"]
expires = "2026-12-31"
note = "Stripe live key"
`
	if err := os.WriteFile(tomlPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(tomlPath)
	if err != nil {
		t.Fatal(err)
	}
	sp, ok := loaded.Secrets["STRIPE_SECRET_KEY"]
	if !ok || sp.Expires != "2026-12-31" || sp.Note != "Stripe live key" || !loaded.HostAllowed("api.stripe.com", "STRIPE_SECRET_KEY") {
		t.Fatalf("unexpected loaded secret policy: %+v", sp)
	}
}
