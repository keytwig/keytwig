package config

import "testing"

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
