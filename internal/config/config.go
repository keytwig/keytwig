// Package config loads ~/.config/keytwig/config.toml.
package config

import (
	"errors"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config lets the user say which folders belong to agent harnesses (their
// secrets stay where they are) and which to skip entirely.
type Config struct {
	// Harness: folders owned by agent harnesses. Their .env files are
	// reported but never proposed for import.
	Harness []string `toml:"harness"`
	// Ignore: folders not scanned at all.
	Ignore []string `toml:"ignore"`
	// Agents: which secrets each agent may receive. The agent is named by
	// --agent or KEYTWIG_AGENT (harness installs set it). "default" applies
	// to unnamed or unlisted agents. No [agents] table = everything allowed.
	// This is a guardrail, not isolation: processes running as the same OS
	// user can still read the vault.
	Agents map[string]AgentPolicy `toml:"agents"`
	// Secrets: per-secret metadata and HTTP host allowlists.
	Secrets map[string]SecretPolicy `toml:"secrets"`
}

// SecretPolicy constrains where a secret may be sent over HTTP and tracks expiry.
type SecretPolicy struct {
	AllowedHosts []string `toml:"allowed_hosts"`
	Expires      string   `toml:"expires"`
	Note         string   `toml:"note"`
}

// AgentPolicy: glob patterns on secret names (path.Match syntax, e.g. "ACME_*").
// Empty allow = all; deny wins over allow.
type AgentPolicy struct {
	Allow []string `toml:"allow"`
	Deny  []string `toml:"deny"`
}

func matchAny(pats []string, name string) bool {
	for _, p := range pats {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

// Allowed tells whether agent may receive a secret known by names (its
// canonical name plus aliases): denied if any name matches deny, allowed if
// allow is empty or any name matches it. So an alias cannot dodge a deny.
func (c Config) Allowed(agent string, names ...string) bool {
	if len(c.Agents) == 0 {
		return true
	}
	pol, ok := c.Agents[agent]
	if !ok || agent == "" {
		if pol, ok = c.Agents["default"]; !ok {
			return true
		}
	}
	for _, n := range names {
		if matchAny(pol.Deny, n) {
			return false
		}
	}
	if len(pol.Allow) == 0 {
		return true
	}
	for _, n := range names {
		if matchAny(pol.Allow, n) {
			return true
		}
	}
	return false
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if strings.HasPrefix(h, "[") && strings.Contains(h, "]") {
		if parsed, _, err := net.SplitHostPort(h); err == nil {
			h = parsed
		} else {
			h = strings.Trim(h, "[]")
		}
	} else if strings.Count(h, ":") == 1 {
		if parsed, _, err := net.SplitHostPort(h); err == nil {
			h = parsed
		}
	}
	h = strings.TrimSuffix(h, ".")
	return strings.ToLower(h)
}

// AllowedHosts returns deduplicated, sorted allowed HTTP hosts across names
// (canonical name and any aliases).
func (c Config) AllowedHosts(names ...string) []string {
	if len(c.Secrets) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		sp, ok := c.Secrets[n]
		if !ok {
			continue
		}
		for _, h := range sp.AllowedHosts {
			nh := normalizeHost(h)
			if nh == "" || seen[nh] {
				continue
			}
			seen[nh] = true
			out = append(out, nh)
		}
	}
	sort.Strings(out)
	return out
}

// HostAllowed reports whether host is explicitly permitted for any of names.
// Secure by default: empty allowed_hosts returns false.
func (c Config) HostAllowed(host string, names ...string) bool {
	nh := normalizeHost(host)
	if nh == "" {
		return false
	}
	allowed := c.AllowedHosts(names...)
	if len(allowed) == 0 {
		return false
	}
	for _, pat := range allowed {
		if strings.HasPrefix(pat, "*.") {
			suffix := pat[1:] // ".example.com"
			if len(nh) > len(suffix) && strings.HasSuffix(nh, suffix) {
				return true
			}
			continue
		}
		if nh == pat {
			return true
		}
	}
	return false
}

// DefaultHarness are well-known harness state folders, relative to $HOME.
var DefaultHarness = []string{
	".hermes", ".openclaw", ".claude", ".codex", ".gemini", ".grok", ".pi",
	".cursor", ".continue", ".aider", ".config/OpenBot", "OpenBot", ".config/Hermes",
}

func Load(path string) (Config, error) {
	var c Config
	if _, err := toml.DecodeFile(path, &c); err != nil && !errors.Is(err, os.ErrNotExist) {
		return c, err
	}
	return c, nil
}

// Expand turns ~ and relative entries into absolute, clean paths.
func Expand(list []string) []string {
	home, _ := os.UserHomeDir()
	out := make([]string, 0, len(list))
	for _, p := range list {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		switch {
		case p == "~":
			p = home
		case strings.HasPrefix(p, "~/"):
			p = filepath.Join(home, p[2:])
		case !filepath.IsAbs(p):
			p = filepath.Join(home, p)
		}
		out = append(out, filepath.Clean(p))
	}
	return out
}

// HarnessPaths = defaults + user entries, absolute.
func (c Config) HarnessPaths() []string {
	return Expand(append(append([]string{}, DefaultHarness...), c.Harness...))
}

func (c Config) IgnorePaths() []string { return Expand(c.Ignore) }
