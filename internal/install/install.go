// Package install registers the keytwig MCP server in agent harnesses.
// Each harness gets `keytwig mcp --agent <harness>` so per-agent policies apply.
package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/BurntSushi/toml"
)

type Result struct {
	Harness string `json:"harness"`
	Path    string `json:"path"`
	Changed bool   `json:"changed"`
	OK      bool   `json:"ok,omitempty"`
	Note    string `json:"note,omitempty"`
}

var Supported = []string{"claude", "codex", "cursor", "windsurf", "hermes", "grok", "antigravity"}

// detect: harness → marker path relative to home
var markers = map[string]string{
	"claude":   ".claude",
	"codex":    ".codex",
	"cursor":   ".cursor",
	"windsurf": filepath.Join(".codeium", "windsurf"),
	"hermes":   ".hermes/config.yaml",
	"grok":     ".grok",
}

func resolveHome(home string) (string, error) {
	if home != "" {
		return home, nil
	}
	return os.UserHomeDir()
}

// Install configures one harness, or every detected one with "all".
func Install(harness, bin, home string, dryRun bool) ([]Result, error) {
	var err error
	home, err = resolveHome(home)
	if err != nil {
		return nil, err
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
		list = detectedHarnesses(home)
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
		case "windsurf":
			r, err = jsonServers(h, filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), bin, false, dryRun)
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

// Uninstall removes the keytwig MCP server entry from one harness or all configured ones.
func Uninstall(harness, home string, dryRun bool) ([]Result, error) {
	var err error
	home, err = resolveHome(home)
	if err != nil {
		return nil, err
	}
	list := []string{harness}
	if harness == "all" {
		list = Supported
	}
	var out []Result
	for _, h := range list {
		switch h {
		case "claude":
			r, err := uninstallJSON(h, filepath.Join(home, ".claude.json"), dryRun)
			if err != nil {
				return out, err
			}
			if harness != "all" || r.Changed {
				out = append(out, r)
			}
		case "cursor":
			r, err := uninstallJSON(h, filepath.Join(home, ".cursor", "mcp.json"), dryRun)
			if err != nil {
				return out, err
			}
			if harness != "all" || r.Changed {
				out = append(out, r)
			}
		case "windsurf":
			r, err := uninstallJSON(h, filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), dryRun)
			if err != nil {
				return out, err
			}
			if harness != "all" || r.Changed {
				out = append(out, r)
			}
		case "codex", "grok":
			r, err := uninstallTOML(h, filepath.Join(home, "."+h, "config.toml"), dryRun)
			if err != nil {
				return out, err
			}
			if harness != "all" || r.Changed {
				out = append(out, r)
			}
		case "antigravity":
			dirs := antigravityDirs(home)
			if len(dirs) == 0 && harness != "all" {
				return out, errors.New("no Antigravity config folder found")
			}
			for _, d := range dirs {
				r, err := uninstallJSON(h, filepath.Join(d, "mcp_config.json"), dryRun)
				if err != nil {
					return out, err
				}
				if harness != "all" || r.Changed {
					out = append(out, r)
				}
			}
		case "hermes":
			r, err := uninstallHermes(filepath.Join(home, ".hermes", "config.yaml"), dryRun)
			if err != nil {
				return out, err
			}
			if harness != "all" || r.Changed {
				out = append(out, r)
			}
		default:
			return out, fmt.Errorf("unsupported harness %q (supported: %s, all)", h, strings.Join(Supported, ", "))
		}
	}
	return out, nil
}

// Check inspects every supported harness config, returning those where keytwig
// is registered along with whether the configured binary exists and is executable.
func Check(home string) []Result {
	home, err := resolveHome(home)
	if err != nil {
		return nil
	}
	type target struct {
		harness string
		path    string
		format  string
	}
	targets := []target{
		{"claude", filepath.Join(home, ".claude.json"), "json"},
		{"cursor", filepath.Join(home, ".cursor", "mcp.json"), "json"},
		{"windsurf", filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), "json"},
		{"codex", filepath.Join(home, ".codex", "config.toml"), "toml"},
		{"grok", filepath.Join(home, ".grok", "config.toml"), "toml"},
		{"hermes", filepath.Join(home, ".hermes", "config.yaml"), "yaml"},
	}
	for _, d := range antigravityDirs(home) {
		targets = append(targets, target{"antigravity", filepath.Join(d, "mcp_config.json"), "json"})
	}

	var out []Result
	for _, t := range targets {
		raw, err := os.ReadFile(t.path)
		if err != nil {
			continue
		}
		var cmd string
		var configured bool
		switch t.format {
		case "json":
			cmd, configured = checkJSON(raw)
		case "toml":
			cmd, configured = checkTOML(raw)
		case "yaml":
			cmd, configured = checkHermes(raw)
		}
		if !configured {
			continue
		}
		ok, note := checkBinary(cmd)
		out = append(out, Result{Harness: t.harness, Path: t.path, OK: ok, Note: note})
	}
	return out
}

func detectedHarnesses(home string) []string {
	var list []string
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
	return list
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

func uninstallJSON(h, path string, dryRun bool) (Result, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Result{Harness: h, Path: path, Note: "not configured"}, nil
	}
	if err != nil {
		return Result{}, err
	}
	data := map[string]any{}
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &data); err != nil {
			return Result{}, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	servers, _ := data["mcpServers"].(map[string]any)
	if _, ok := servers["keytwig"]; !ok {
		return Result{Harness: h, Path: path, Note: "not configured"}, nil
	}
	delete(servers, "keytwig")
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

func uninstallTOML(h, path string, dryRun bool) (Result, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Result{Harness: h, Path: path, Note: "not configured"}, nil
	}
	if err != nil {
		return Result{}, err
	}
	lines := strings.Split(string(raw), "\n")
	var kept []string
	found := false
	inSection := false
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "[mcp_servers.keytwig]" {
			found = true
			inSection = true
			continue
		}
		if inSection {
			if strings.HasPrefix(t, "[") {
				inSection = false
			} else {
				continue
			}
		}
		kept = append(kept, l)
	}
	if !found {
		return Result{Harness: h, Path: path, Note: "not configured"}, nil
	}
	updated := strings.TrimRight(strings.Join(kept, "\n"), "\n") + "\n"
	if strings.TrimSpace(updated) == "" {
		updated = ""
	}
	if !dryRun {
		if err := writeWithBackup(path, []byte(updated)); err != nil {
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

func uninstallHermes(path string, dryRun bool) (Result, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Result{Harness: "hermes", Path: path, Note: "not configured"}, nil
	}
	if err != nil {
		return Result{}, err
	}
	lines := strings.Split(string(raw), "\n")
	var kept []string
	inMcp := false
	skipping := false
	keyIndent := 0
	found := false
	for _, l := range lines {
		t := strings.TrimSpace(l)
		indent := len(l) - len(strings.TrimLeft(l, " "))
		if skipping {
			if t != "" && indent <= keyIndent {
				skipping = false
			} else {
				continue
			}
		}
		if t != "" && !strings.HasPrefix(t, "#") && indent == 0 {
			inMcp = t == "mcp_servers:"
		}
		if inMcp && indent > 0 && strings.HasPrefix(t, "keytwig:") {
			found = true
			skipping = true
			keyIndent = indent
			continue
		}
		kept = append(kept, l)
	}
	if !found {
		return Result{Harness: "hermes", Path: path, Note: "not configured"}, nil
	}
	updated := strings.TrimRight(strings.Join(kept, "\n"), "\n") + "\n"
	if !dryRun {
		if err := writeWithBackup(path, []byte(updated)); err != nil {
			return Result{}, err
		}
	}
	return Result{Harness: "hermes", Path: path, Changed: true, Note: "restart hermes to apply"}, nil
}

func checkJSON(raw []byte) (string, bool) {
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return "", false
	}
	servers, _ := data["mcpServers"].(map[string]any)
	entry, ok := servers["keytwig"].(map[string]any)
	if !ok {
		return "", false
	}
	cmd, _ := entry["command"].(string)
	return cmd, true
}

func checkTOML(raw []byte) (string, bool) {
	var data map[string]any
	if _, err := toml.Decode(string(raw), &data); err != nil {
		return "", false
	}
	servers, _ := data["mcp_servers"].(map[string]any)
	entry, ok := servers["keytwig"].(map[string]any)
	if !ok {
		return "", false
	}
	cmd, _ := entry["command"].(string)
	return cmd, true
}

func checkHermes(raw []byte) (string, bool) {
	lines := strings.Split(string(raw), "\n")
	inMcp := false
	inKeytwig := false
	keyIndent := 0
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		indent := len(l) - len(strings.TrimLeft(l, " "))
		if indent == 0 {
			inMcp = t == "mcp_servers:"
			inKeytwig = false
			continue
		}
		if inMcp && !inKeytwig && strings.HasPrefix(t, "keytwig:") {
			inKeytwig = true
			keyIndent = indent
			continue
		}
		if inKeytwig {
			if indent <= keyIndent {
				return "", true
			}
			if strings.HasPrefix(t, "command:") {
				v := strings.TrimSpace(strings.TrimPrefix(t, "command:"))
				v = strings.Trim(v, `"'`)
				return v, true
			}
		}
	}
	return "", inKeytwig
}

func checkBinary(bin string) (bool, string) {
	if bin == "" {
		return false, "missing command path"
	}
	path := bin
	if !strings.ContainsAny(bin, `/\`) {
		p, err := exec.LookPath(bin)
		if err != nil {
			return false, "command not found in PATH: " + bin
		}
		path = p
	}
	st, err := os.Stat(path)
	if err != nil {
		return false, "binary missing: " + bin
	}
	if st.IsDir() {
		return false, "command is a directory: " + bin
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o111 == 0 {
		return false, "binary not executable: " + bin
	}
	return true, "ok (" + bin + ")"
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
