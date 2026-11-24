// Package install registers the keytwig MCP server in agent harnesses.
// Each harness gets `keytwig mcp --agent <harness>` so per-agent policies apply.
package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Result struct {
	Harness string `json:"harness"`
	Path    string `json:"path"`
	Changed bool   `json:"changed"`
	Note    string `json:"note,omitempty"`
}

var Supported = []string{"claude", "codex", "cursor", "hermes", "grok", "antigravity"}

// detect: harness → marker path relative to home
var markers = map[string]string{
	"claude": ".claude",
	"codex":  ".codex",
	"cursor": ".cursor",
	"hermes": ".hermes/config.yaml",
	"grok":   ".grok",
}

// Install configures one harness, or every detected one with "all".
func Install(harness, bin, home string, dryRun bool) ([]Result, error) {
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		home = h
	}
	if bin == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		bin = exe
	}
	list := []string{harness}
	if harness == "all" {
		list = nil
		for _, h := range Supported {
			if h == "antigravity" {
				if len(antigravityDirs(home)) > 0 {
					list = append(list, h)
				}
				continue
			}
			if _, err := os.Stat(filepath.Join(home, markers[h])); err == nil {
				list = append(list, h)
			}
		}
	}
	var out []Result
	for _, h := range list {
		var r Result
		var err error
		switch h {
		case "claude":
			r, err = jsonServers(h, filepath.Join(home, ".claude.json"), bin, true, dryRun)
		case "cursor":
			r, err = jsonServers(h, filepath.Join(home, ".cursor", "mcp.json"), bin, false, dryRun)
		case "codex", "grok":
			r, err = tomlServers(h, filepath.Join(home, "."+h, "config.toml"), bin, dryRun)
		case "antigravity":
			dirs := antigravityDirs(home)
			if len(dirs) == 0 {
				return out, errors.New("no Antigravity config folder found")
			}
			for _, d := range dirs {
				r, err := jsonServers(h, filepath.Join(d, "mcp_config.json"), bin, false, dryRun)
				if err != nil {
					return out, err
				}
				out = append(out, r)
			}
			continue
		case "hermes":
			r, err = hermes(filepath.Join(home, ".hermes", "config.yaml"), bin, dryRun)
		default:
			return out, fmt.Errorf("unsupported harness %q (supported: %s, all)", h, strings.Join(Supported, ", "))
		}
		if err != nil {
			return out, err
		}
		out = append(out, r)
	}
	return out, nil
}

func args(h string) []string { return []string{"mcp", "--agent", h} }

func jsonServers(h, path, bin string, typed, dryRun bool) (Result, error) {
	data := map[string]any{}
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Result{}, err
	}
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &data); err != nil {
			return Result{}, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	servers, _ := data["mcpServers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}
	if _, ok := servers["keytwig"]; ok {
		return Result{Harness: h, Path: path, Note: "already configured"}, nil
	}
	entry := map[string]any{"command": bin, "args": args(h)}
	if typed {
		entry["type"] = "stdio"
	}
	servers["keytwig"] = entry
	data["mcpServers"] = servers
	out, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return Result{}, err
	}
	if !dryRun {
		if err := writeWithBackup(path, append(out, '\n')); err != nil {
			return Result{}, err
		}
	}
	return Result{Harness: h, Path: path, Changed: true}, nil
}

// antigravityDirs: standalone (~/.gemini/antigravity) and T3-managed provider configs.
func antigravityDirs(home string) []string {
	var dirs []string
	m, _ := filepath.Glob(filepath.Join(home, ".t3", "userdata", "providers", "antigravity", "*", "config"))
	m = append(m, filepath.Join(home, ".gemini", "antigravity"))
	for _, d := range m {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			dirs = append(dirs, d)
		}
	}
	return dirs
}

func tomlServers(h, path, bin string, dryRun bool) (Result, error) {
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Result{}, err
	}
	s := string(raw)
	if strings.Contains(s, "[mcp_servers.keytwig]") {
		return Result{Harness: h, Path: path, Note: "already configured"}, nil
	}
	block := fmt.Sprintf("\n[mcp_servers.keytwig]\ncommand = %q\nargs = [\"mcp\", \"--agent\", %q]\n", bin, h)
	if !dryRun {
		if err := writeWithBackup(path, []byte(strings.TrimRight(s, "\n")+"\n"+block)); err != nil {
			return Result{}, err
		}
	}
	return Result{Harness: h, Path: path, Changed: true}, nil
}

func hermes(path, bin string, dryRun bool) (Result, error) {
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Result{}, err
	}
	lines := strings.Split(string(raw), "\n")
	mcpIdx := -1
	in := false
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		indent := len(l) - len(strings.TrimLeft(l, " "))
		if indent == 0 {
			in = t == "mcp_servers:"
			if in {
				mcpIdx = i
			}
			continue
		}
		if in && strings.HasPrefix(t, "keytwig:") {
			return Result{Harness: "hermes", Path: path, Note: "already configured"}, nil
		}
	}
	block := []string{
		"  keytwig:",
		"    command: " + bin,
		"    args:",
		"      - mcp",
		"      - --agent",
		"      - hermes",
		"    enabled: true",
	}
	var updated string
	if mcpIdx >= 0 {
		out := append([]string{}, lines[:mcpIdx+1]...)
		out = append(out, block...)
		out = append(out, lines[mcpIdx+1:]...)
		updated = strings.Join(out, "\n")
	} else {
		base := strings.TrimRight(string(raw), "\n")
		if base != "" {
			base += "\n\n"
		}
		updated = base + "mcp_servers:\n" + strings.Join(block, "\n") + "\n"
	}
	if !dryRun {
		if err := writeWithBackup(path, []byte(updated)); err != nil {
			return Result{}, err
		}
	}
	return Result{Harness: "hermes", Path: path, Changed: true, Note: "restart hermes to load it"}, nil
}

func writeWithBackup(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if prev, err := os.ReadFile(path); err == nil {
		if st, err := os.Stat(path); err == nil {
			mode = st.Mode().Perm()
		}
		if err := os.WriteFile(path+".keytwig.bak", prev, 0o600); err != nil {
			return err
		}
	}
	return os.WriteFile(path, content, mode)
}
