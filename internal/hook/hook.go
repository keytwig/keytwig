// Package hook implements a PreToolUse secret guard for AI agent harnesses
// (Claude Code, Cursor) to block direct reads of .env files, vault files,
// credential files, and raw environment dumps.
package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/keytwig/keytwig/internal/scan"
	"github.com/keytwig/keytwig/internal/vault"
)

// Input is the PreToolUse payload sent on stdin by Claude Code / Cursor.
type Input struct {
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
	Cwd       string         `json:"cwd"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// Output is the PreToolUse response written to stdout.
type Output struct {
	HookSpecificOutput *hookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

var fileTools = map[string]bool{
	"read": true, "view": true, "grep": true, "glob": true,
	"edit": true, "write": true, "cat": true,
	"read_file": true, "view_file": true, "grep_search": true, "list_dir": true,
}

var shellTools = map[string]bool{
	"bash": true, "shell": true, "run_command": true, "execute": true, "terminal": true,
}

var (
	shellSplitRe = regexp.MustCompile(`\s*(?:&&|\|\||[;|\n])\s*`)
	envDumpRe    = regexp.MustCompile(`^(?:env(?:\s+(?:-[0iu]|--null))*\s*(?:$|[<>])|printenv(?:\s|$)|(?:export|declare)\s+-[px]+)`)
)

// Run reads a PreToolUse JSON payload from r, evaluates it against p, and writes
// the JSON decision to w.
func Run(r io.Reader, w io.Writer, p vault.Paths) error {
	raw, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		_, err := io.WriteString(w, "{}\n")
		return err
	}
	var in Input
	if err := json.Unmarshal(raw, &in); err != nil {
		// Malformed hook input: fail open so normal tools don't wedge.
		_, werr := io.WriteString(w, "{}\n")
		return werr
	}
	blocked, reason := Evaluate(in, p)
	var out Output
	if blocked {
		out.HookSpecificOutput = &hookSpecificOutput{
			HookEventName:      "PreToolUse",
			PermissionDecision: "deny",
			PermissionDecisionReason: fmt.Sprintf(
				"keytwig blocked direct access to %s. Use keytwig_run (project=true) or keytwig_http so secret values never enter model context.",
				reason,
			),
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// Evaluate checks whether the tool invocation tries to read secret files or dump env directly.
func Evaluate(in Input, p vault.Paths) (bool, string) {
	tool := strings.ToLower(strings.TrimSpace(in.ToolName))
	if fileTools[tool] {
		for _, k := range []string{"file_path", "path", "target_file"} {
			if raw, ok := in.ToolInput[k].(string); ok && strings.TrimSpace(raw) != "" {
				if reason := checkPath(raw, in.Cwd, p); reason != "" {
					return true, reason
				}
			}
		}
		return false, ""
	}
	if shellTools[tool] {
		for _, k := range []string{"command", "cmd"} {
			if cmd, ok := in.ToolInput[k].(string); ok && strings.TrimSpace(cmd) != "" {
				if reason := checkShellCommand(cmd, in.Cwd, p); reason != "" {
					return true, reason
				}
			}
		}
	}
	return false, ""
}

func expandPath(raw, cwd string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, `"'`)
	if raw == "" {
		return ""
	}
	if raw == "~" || strings.HasPrefix(raw, "~/") || strings.HasPrefix(raw, `~\`) {
		if h, err := os.UserHomeDir(); err == nil {
			if raw == "~" {
				raw = h
			} else {
				raw = filepath.Join(h, raw[2:])
			}
		}
	} else if !filepath.IsAbs(raw) && cwd != "" {
		raw = filepath.Join(cwd, raw)
	}
	return filepath.Clean(raw)
}

func checkPath(raw, cwd string, p vault.Paths) string {
	cleaned := expandPath(raw, cwd)
	if cleaned == "" {
		return ""
	}
	base := filepath.Base(cleaned)
	if p.Identity != "" && samePath(cleaned, p.Identity) {
		return "keytwig identity file (" + base + ")"
	}
	if p.Vault != "" && samePath(cleaned, p.Vault) {
		return "keytwig vault file (" + base + ")"
	}
	if base == "vault.age" || (base == "identity.txt" && strings.Contains(strings.ToLower(filepath.ToSlash(cleaned)), "/keytwig/")) {
		return "keytwig vault/identity (" + base + ")"
	}
	if scan.IsEnvName(base) {
		return "env file (" + base + ")"
	}
	if kind := scan.ClassifyTool(cleaned); kind != "" {
		return kind + " credential file (" + base + ")"
	}
	return ""
}

func samePath(a, b string) bool {
	ca, cb := filepath.Clean(a), filepath.Clean(b)
	return ca == cb || strings.EqualFold(ca, cb) && filepath.Separator == '\\'
}

func checkShellCommand(cmd, cwd string, p vault.Paths) string {
	segments := shellSplitRe.Split(cmd, -1)
	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		fields := strings.Fields(seg)
		if len(fields) == 0 {
			continue
		}
		first := strings.Trim(fields[0], `"'`)
		firstBase := filepath.Base(first)
		if firstBase == "keytwig" || firstBase == "keytwig.exe" {
			// Still inspect command substitution inside keytwig args just in case.
			if !strings.Contains(seg, "$(") && !strings.Contains(seg, "`") {
				continue
			}
		}
		if envDumpRe.MatchString(seg) {
			return "raw environment dump"
		}
		for _, tok := range fields {
			tok = strings.Trim(tok, `"'`)
			if tok == "" {
				continue
			}
			// Handle redirections like <.env or --file=.env
			candidates := []string{tok}
			if idx := strings.IndexByte(tok, '='); idx > 0 {
				candidates = append(candidates, tok[idx+1:])
			}
			for _, c := range candidates {
				c = strings.TrimLeft(c, "<>")
				c = strings.Trim(c, `"'`)
				if c == "" || strings.HasPrefix(c, "-") {
					continue
				}
				if reason := checkPath(c, cwd, p); reason != "" {
					return reason
				}
			}
		}
	}
	return ""
}
