// Package config loads ~/.config/keytwig/config.toml.
package config

import (
	"errors"
	"os"
	"path"
	"path/filepath"
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
